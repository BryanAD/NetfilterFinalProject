#include "my_netfilter.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>

#define MAX_SIZE 1024

static struct directory *mf_proc_file;
char* buffer;
unsigned long buffer_position;
static struct nf_hook_ops nfho_in;
statis struct nf_hook_ops nfho_out;

struct firewall_policy {
	char i_o;		// 0=neither 1=in 2=out
	char* start_ip;
	char* start_netmask;
	char* start_port;	// between 0 and 2^32
	char* end_ip;
	char* end_netmask;
	char* end_port;
	char protocol;		// 0=all, 1=tcp, 2=udp
	char block;		// 0=block, 1=unblock
} firewall_policy;

struct policy_list {
	char i_o;
	char* start_ip;
	char* start_netmask;
	char* start_port;
	char* end_ip;
	char* end_netmask;
	char* end_port;
	char protocol;
	char block;
	struct list_head list;
} policy_list;

static struct policy_list mpolicies;

void int_str_conv(unsigned int port, char* str) {
	sprintf(str, "%u", port);
}

unsigned int str_int_conv(char* str) {
	unsigned int port = 0;    
	int i = 0;
	if (str==NULL) {
		return 0;
	} 
	while (port_str[i]!='') {
		port = port*10 + (port_str[i]-'0');
		++i;
	}
	return port;
}

void start_policy(struct firewall_policy* policy) {
	policy->i_o = 0;
	policy->start_ip = (char *)kmalloc(16, GFP_KERNEL);
	policy->start_netmask = (char *)kmalloc(16, GFP_KERNEL);
	policy->start_port = (char *)kmalloc(16, GFP_KERNEL);
	policy->end_ip = (char *)kmalloc(16, GFP_KERNEL);
	policy->end_netmask = (char *)kmalloc(16, GFP_KERNEL);
	policy->end_port = (char *)kmalloc(16, GFP_KERNEL);
	policy->protocol = 0;
	policy->block = 0;
}

void delete_policy(int list_num){
	int i = 0;
	struct list_head* p,* q;
	struct policy_list* policy;
	printk(KERN_INFO "delete a rule: %dn", list_num);
	list_for_each_safe(p, q, &mpolicies.list)
		i++;
		if (i == list_num){
			policy = list_entry(p, struct policy_list, list);
			list_del(p);
			kfree(policy);
			return;
		}
	}
}

bool compare_ips(unsigned int ip, unsigned int policy, unsigned int mask) {
	unsigned int tmp = ntohl(ip);
	int cmp_len = 32;
	int i, j;
	i = 0;
	j = 0;
	printk(KERN_INFO "compare_ips: %u <=> %un", tmp, policy);
	if (mask != 0) {
		cmp_len = 0;
		for (i = 0; i < 32; i++){
			if (mask & (1 << (32-1-i)))
				cmp_len++;
		else
			break;
		}
	}
	for (i = 31; j < cmp_len; i--, j++) {
		if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
			printk(KERN_INFO "ip compare: %d bit doesn't matchn", (32-i));
			return false;
		}
	}
	return true;
}

unsigned int inbound_filter(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in,
						const struct net_device* out, int (*okfn)(struct sk_buff*))
{
	int index = 0;
	int block = 0;	
	for(index = 0; index < num_of_rules; index ++) {
		if(minifw_rules_table[index].hook_entry == NF_INET_LOCAL_IN) 
		{
			action = Check_Rule(skb, &minifw_rules_table[index]);
			if(!action)	{				
				if (minifw_rules_table[index].action == BLOCK)
					return NF_DROP;
				else
					return NF_ACCEPT;
			}			
		}	
	}
	return NF_ACCEPT;
}

unsigned int outbound_filter(unsigned int hooknum, struct sk_buff *skb, const struct net_device* in,
							const struct net_device* out, int (*okfn)(struct sk_buff *)) 
{
	int index = 0;
	int block = 0;	
	for(index = 0; index < num_of_rules; index ++) {
		if(minifw_rules_table[index].hook_entry == NF_INET_LOCAL_OUT) {
			action = Check_Rule(skb, &minifw_rules_table[index]);
			if(!action) {				
				if (minifw_rules_table[index].action == BLOCK)
					return NF_DROP;
				else
					return NF_ACCEPT;
			}
		}	
	}
	return NF_ACCEPT;
}

int init_module() {
	
}

void cleanup_module() {

}
