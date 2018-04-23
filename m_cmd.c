#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>

#define PORT_NUM_MAX USHRT_MAX

enum mode {
	NONE = 0,
	ADD = 1,
	REMOVE = 2,
	VIEW = 3
};


struct net_rule{
	int in_out;		// 1=in, 2=out
	uint32_t startIP;
	uint32_t startMask;
	uint32_t endIP;
	uint32_t endMask;
};

struct net_ctl{
	enum mode mmode;
	struct net_rule mrule;
};

// Prints functions and params
static void print_usage(void){
	printf("Usage: RULE_OPTIONS..\n"
	       "Netfilter implements an exact match algorithm, where "
	       "unspecified options are ignored.\n"
	       "-i --in             input\n"
	       "-o --out            output\n"
	       "-s --s_ip IPADDR    source ip address\n"
	       "-m --s_mask MASK    source mask\n"
	       "-d --d_ip IPADDR    destination ip address\n"
	       "-n --d_mask MASK    destination mask\n"
	       "-a --add            add a rule\n"
	       "-r --remove         remove a rule\n"
	       "-v --view           view rules\n"
	       "-h --help           this usage\n");
}


// Send command to module
static void send_instruction(struct net_ctl* ctl){
	FILE* fp;
	int byte_count;

	fp = fopen("netfilter_file", "w");
	if(fp == NULL) {
		printf("An device file (%s) cannot be opened.\n",
		       "netfilter_file");
		return;
	}
	byte_count = fwrite(ctl, 1, sizeof(*ctl), fp);
	if(byte_count != sizeof(*ctl))
		printf("Write process is incomplete. Please try again.\n");

	fclose(fp);
}


// Print all existing rules from module
static void view_rules(void){
	FILE* fp;
	char* buffer;
	int byte_count;
	struct in_addr addr;
	struct net_rule* rule;

	fp = fopen("netfilter_file", "r");
	if(fp == NULL) {
		printf("An device file (%s) cannot be opened.\n",
		       "netfilter_file");
		return;
	}

	buffer = (char *)malloc(sizeof(*rule));
	if(buffer == NULL) {
		printf("Rule cannot be printed duel to insufficient memory\n");
		return;
	}

	/* Each rule is printed line-by-line. */
	printf("I/O  "
	       "S_Addr           S_Mask           D_Addr           "
	       "D_Mask\n");
	while((byte_count = fread(buffer, 1, sizeof(struct net_rule), fp)) > 0) {
		rule = (struct net_rule *)buffer;
		printf("%-3s  ", rule->in_out ? "In" : "Out");
		addr.s_addr = rule->startIP;
		printf("%-15s  ", inet_ntoa(addr));
		addr.s_addr = rule->startMask;
		printf("%-15s  ", inet_ntoa(addr));
		addr.s_addr = rule->endIP;
		printf("%-15s  ", inet_ntoa(addr));
		addr.s_addr = rule->endMask;
		printf("%-15s  ", inet_ntoa(addr));
	}
	free(buffer);
	fclose(fp);
}


// Parse a string and check its range
static int64_t parse_number(const char *str, uint32_t min_val, uint32_t max_val){
	uint32_t num;
	char *end;

	num = strtol(str, &end, 10);
	if(end == str || (num > max_val) || (num < min_val))
		return -1;

	return num;
}


// Parse arguments
static int parse_arguments(int argc, char **argv, struct net_ctl *ret_ctl){
	int opt;
	int64_t lnum;
	int opt_index;
	struct net_ctl ctl = {};
	struct in_addr addr;

	/* Long option configuration */
	static struct option long_options[] = {
		{"in", no_argument, 0, 'i'},
		{"out", no_argument, 0, 'o'},
		{"s_ip", required_argument, 0, 's'},
		{"s_mask", required_argument, 0, 'm'},
		{"d_ip", required_argument, 0, 'd'},
		{"d_mask", required_argument, 0, 'n'},
		{"add", no_argument, 0, 'a'},
		{"remove", no_argument, 0, 'r'},
		{"view", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	if(argc == 1) {
		print_usage();
		return 0;
	}

	ctl.mmode = NONE;
	ctl.mrule.in_out = -1;
	while(1) {
		opt_index = 0;
		opt = getopt_long(argc, argv, "ios:m:d:n:arvh",
				  long_options, &opt_index);
		if(opt == -1) {
			break;
		}

		switch(opt) {
		case 'i':	// Make Inbound Rule
			if(ctl.mrule.in_out == 0) {
				printf("Please select either In or Out\n");
				return -1;
			}
			ctl.mrule.in_out = 1;
			break;
		case 'o':	// Make Outbound Rule
			if(ctl.mrule.in_out == 1) {
				printf("Please select either In or Out\n");
				return -1;
			}
			ctl.mrule.in_out = 0;			
			break;
		case 's':	// Starting IP address
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid source ip address\n");
				return -1;
			}
			ctl.mrule.StartIP = addr.s_addr;
			break;
		case 'm':	// Starting Subnet Mask
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid source subnet mask\n");
				return -1;
			}
			ctl.mrule.StartMask = addr.s_addr;
			break;
		case 'd':	// End IP Address
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid destination ip address\n");
				return -1;
			}
			ctl.mrule.EndIP = addr.s_addr;
			break;
		case 'n':	// End Subnet Mask
			if(inet_aton(optarg, &addr) == 0) {
				printf("Invalid destination subnet mask\n");
				return -1;
			}
			ctl.mrule.EndMask = addr.s_addr;
			break;
		case 'a':	// Add rule
			if(ctl.mmode != MFW_NONE) {
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mmode = ADD;
			break;
		case 'r':	// Remove rule
			if(ctl.mmode != NONE) {
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mmode = REMOVE;
			break;
		case 'v':	// View rules
			if(ctl.mmode != NONE) {
				printf("Only one mode can be selected.\n");
				return -1;
			}
			ctl.mmode = VIEW;
			break;
		case 'h':
		case '?':
		default:
			print_usage();
			return -1;
		}
	}
	if(ctl.mmode == NONE) {
		printf("Please specify mode --(add|remove|view)\n");
		return -1;
	}
	if(ctl.mmode != VIEW && ctl.mrule.in_out == -1) {
		printf("Please specify either In or Out\n");
		return -1;
	}

	*ret_ctl = ctl;
	return 0;
}


int main(int argc, char *argv[])
{
	struct net_ctl ctl = {};
	int ret;

	ret = parse_arguments(argc, argv, &ctl);
	if(ret < 0)
		return ret;

	switch(ctl.mmode) {
	case ADD:
	case REMOVE:
		send_instruction(&ctl);
		break;
	case VIEW:
		view_rules();
		break;
	default:
		return 0;
	}
}