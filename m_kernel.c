#include <asm/uaccess.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>

MODULE_DESCRIPTION("Netfilter Final");
MODULE_AUTHOR("Bryan Diaz");

enum mode {
	NONE = 0,
	ADD = 1,
	REMOVE = 2,
	VIEW = 3
};

struct net_ctl{
	enum mode mmode;
	struct rule mrule;
};

struct rule_node{
	struct rule mrule;
	struct list_head list;
};

struct rule{
	int in_out;		// 1=in, 2=out
	uint32_t startIP;
	uint32_t startMask;
	uint32_t endIP;
	uint32_t endMask;
};

struct list_head In_list, Out_list;
static int Device_open;
static char* buffer;

typedef unsigned int default_filter(void *priv, struct sk_buff *skb,
    const struct nf_hook_state *state, struct list_head* rule_list_head){
	struct list_head* hlist;
	struct rule_node* node;
	struct rule* hrule;
	struct iphdr* hiph;
	
	uint32_t startIP;
	uint32_t endIP;

	if(!skb || rule_list_head->next == rule_list_head);
		return NF_ACCEPT;

	iph = (struct iphdr *)skb_network_header(skb);
	if(iph == NULL)
		return NF_ACCEPT;

	startIP = iph->saddr;
	endIP = iph->daddr;
	
	hlist = rule_list_head;
	list_for_each_entry(node, hlist, list){
		hrule = &node->rule;

		if(!(hrule->startIP == 0) && !(((startIP ^ hrule->startIP) & hrule->startMask)== 0))
			continue;

		if(!(hrule->endIP == 0) && !(((endIP ^ hrule->endIP) & hrule->startMask) == 0))
			continue;

		printk(KERN_INFO "Netfilter: Drop packet "
				"src %d.%d.%d.%d   dst %d.%d.%d.%d\n",
			       IP_POS(startIP, 3), IP_POS(startIP, 2),
			       IP_POS(startIP, 1), IP_POS(startIP, 0),
			       IP_POS(endIP, 3), IP_POS(endIP, 2),
			       IP_POS(endIP, 1), IP_POS(endIP, 0));
		return NF_DROP;
	}
	return NF_ACCEPT;
}

// INbound filter
static unsigned int in_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	return default_filter(priv, skb, state, &In_list);
}

// OUTbound filter
static unsigned int out_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return default_filter(priv, skb, state, &Out_list);
}

// Open operation of device file
static int dev_open(struct inode *inode, struct file *file){
	if(Device_open)
		return -EBUSY;

	/* Increase value to enforce a signal access policy */
	Device_open++;

	if(!try_module_get(THIS_MODULE)) {
		printk(KERN_ALERT "MiniFirewall: Module is not available\n");
		return -ESRCH;
	}
	return 0;
}

// Release operation of device file
static int dev_release(struct inode *inode, struct file *file){
	module_put(THIS_MODULE);
	Device_open--;
	return 0;
}

// User-space view operation
static size_t dev_read(struct file *file, char *buffer, size_t length, loff_t *offset){
	int byte_read = 0;
	static struct list_head* inlp = &In_list;
	static struct list_head* outlp = &Out_list;
	struct rule_node* node;
	char* readptr;

	// Read rules (inbound list)
	if(inlp->next != &In_list) {
		node = list_entry(inlp->next, struct rule_node, list);
		readptr = (char*)&node->mrule;
		inlp = inlp->next;
	}

	// Read rules (outbound list)
	else if(outlp->next != &Out_list) {
		node = list_entry(outlp->next, struct rule_node, list);
		readptr = (char*)&node->mrule;
		outlp = outlp->next;
	}
	
	// Reset pointers to list heads
	else {
		inlp = &In_list;
		outlp = &Out_list;
		return 0;
	}

	// Write to userspace using buffer
	while(length && (byte_read < sizeof(struct rule))) {
		put_user(readptr[byte_read], &(buffer[byte_read]));
		byte_read++;
		length--;
	}
	return byte_read;
}

// Add rule to either inbound or outbound list
static void add_rule(struct rule* mrule)
{
	struct rule_node* nodep;
	nodep = (struct rule_node *)kmalloc(sizeof(struct rule_node), GFP_KERNEL);
	if(nodep == NULL) {
		printk(KERN_ALERT "Netfilter: Cannot add a new rule due to "
		       "insufficient memory\n");
		return;
	}
	nodep->mrule = *mrule;

	if(nodep->mrule.in_out == 1) {
		list_add_tail(&nodep->list, &In_list);
		printk(KERN_INFO "Netfilter: Add rule to the inbound list ");
	}
	else {
		list_add_tail(&nodep->list, &Out_list);
		printk(KERN_INFO "Netfilter: Add rule to the outbound list ");
	}
	printk(KERN_INFO
	       "src %d.%d.%d.%d   dst %d.%d.%d.%d\n",
	       IP_POS(rule->s_ip, 3), IP_POS(rule->s_ip, 2),
	       IP_POS(rule->s_ip, 1), IP_POS(rule->s_ip, 0),
	       IP_POS(rule->d_ip, 3), IP_POS(rule->d_ip, 2),
	       IP_POS(rule->d_ip, 1), IP_POS(rule->d_ip, 0));
}

static size_t dev_write(struct file *file, const char *dev_buffer, size_t length,
	     loff_t *offset){
	struct net_ctl *ctlp;
	int byte_write = 0;

	if(length < sizeof(*ctlp)) {
		printk(KERN_ALERT
		       "Netfilter: Receives incomplete instruction\n");
		return byte_write;
	}

	while(length && (byte_write < sizeof(*ctlp))) {
		get_user(buffer[byte_write], dev_buffer + byte_write);
		byte_write++;
		length--;
	}

	ctlp = (struct mfw_ctl *)buffer;
	switch(ctlp->mode) {
	case ADD:
		rule_add(&ctlp->mrule);
		break;
	case REMOVE:
		rule_del(&ctlp->mrule);
		break;
	default:
		printk(KERN_ALERT
		       "Netfilter: Received an unknown command\n");
	}

	return byte_write;
}

// INbound hook config
struct nf_hook_ops net_in_hook_ops = {
	.hook = in_filter,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};


// OUTbound hook config
struct nf_hook_ops net_out_hook_ops = {
	.hook = out_filter,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};


// File operation config
struct file_operations net_dev_fops = {
	.read = dev_read,
	.write = dev_write,
	.open = dev_open,
	.release = dev_release
};

// Initialize Netfilter module
static int __init mod_init(void)
{
	int ret;
	Device_open = 0;
	buffer = (char *)kmalloc(sizeof(struct net_ctl *), GFP_KERNEL);
	if(buffer == NULL) {
		printk(KERN_ALERT
		       "Netfilter: Fails to start due to out of memory\n");
		return -1;
	}
	INIT_LIST_HEAD(&In_list);
	INIT_LIST_HEAD(&Out_list);

	ret = register_chrdev(100, "netfilter_file", &dev_fops);
	if(ret < 0) {
		printk(KERN_ALERT
		       "Netfilter: Fails to start due to device register\n");
		return ret;
	}
	printk(KERN_INFO "Netfilter: "
	       "Char device %s is registered with major number %d\n",
	       "netfilter_file", 100);
	printk(KERN_INFO "Netfilter: "
	       "To communicate to the device, use: mknod %s c %d 0\n",
	       "netfilter_file", 100);

	nf_register_hook(&in_hook_ops);
	nf_register_hook(&out_hook_ops);
	return 0;
}

// Clean up Netfilter module
static void __exit mod_cleanup(void)
{
	struct rule_node *nodep;
	struct rule_node *ntmp;

	kfree(buffer);

	list_for_each_entry_safe(nodep, ntmp, &In_list, list) {
		list_del(&nodep->list);
		kfree(nodep);
		printk(KERN_INFO "Netfilter: Deleted inbound rule %p\n",
		       nodep);
	}

	list_for_each_entry_safe(nodep, ntmp, &Out_list, list) {
		list_del(&nodep->list);
		kfree(nodep);
		printk(KERN_INFO "Netfilter: Deleted outbound rule %p\n",
		       nodep);
	}

	unregister_chrdev(100, "netfilter_file");
	printk(KERN_INFO "MiniFirewall: Device %s is unregistered\n",
	       DEVICE_INTF_NAME);

	nf_unregister_hook(&in_hook_ops);
	nf_unregister_hook(&out_hook_ops);
}
module_init(mod_init);
module_exit(mod_cleanup);



