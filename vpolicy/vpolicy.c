/* 
 * Copyright (C) 2014 Joshua Hare, Lance Hartung, and Suman Banerjee.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <math.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>  // htonl
#include <sys/socket.h> // IPPROTO

#include <linux/types.h>


#include "../virtIoctl.h"
#include "../virtPolicyTypes.h"


#define SOURCE 0
#define DEST 1

char *version = "vpolicy 1.4 (2014-06-19)";

int flag_tuple = 0;
int flag_src_tuple = 0;
int flag_dst_tuple = 0;
int flag_application = 0;
int flag_device = 0;
int flag_route = 0;

// TODO:
// - use the kernel header file
// - generate policy and traffic to test policy
// - expose an API for algorithms to inject policies
// - make a rule set to test validity of policy changes
//   - i.e., if flow was previously NATed it cannot change to encap
// - parse policy file on startup
// - allow algo to register with kernel and set a mode of operation (epoch based, openflow)
// - convert IP strings to hex based values (host or network order?)
// - try to optimize the policies so that the kernel list is short
// - need clean syntax to pass down interface list plus rate limit parameters

//static int parse_policy_type(const char* type, struct policy_req *policy);
static int parse_policy_table(int argc, char *argv[], int index, struct policy_req *policy);
//static int parse_ratelimit(int argc, char *argv[], int index, struct policy_req *policy);

static int parse_address(char *arg, struct policy_req *policy, int type);
static int parse_protocol(char *arg, struct policy_req *policy);
static int parse_port(char *arg, struct policy_req *policy, int type);
static int parse_action(char *arg, struct policy_req *policy);
static int parse_link_select(char *arg, struct policy_req *policy);

static int check_policy_for_conflicts(struct policy_req *policy);

static int list_policies();

enum {
    OPTION_PROTO = 256,
    OPTION_SPORT,
    OPTION_DPORT,
    OPTION_ACTION,
    OPTION_ENCRYPT,
    OPTION_COMPRESS,
    OPTION_DUPLICATE,
    OPTION_MULTIPATH,
    OPTION_RETX,
};

enum {
    CMD_LIST,
    CMD_APPEND,
    CMD_DELETE,
    CMD_INSERT,
};

const struct option longopts[] = {
    {.name = "list",        .has_arg = 0,  .flag = 0,  .val = 'L'},
    {.name = "append",      .has_arg = 1,  .flag = 0,  .val = 'A'},
    {.name = "delete",      .has_arg = 1,  .flag = 0,  .val = 'D'},
    {.name = "insert",      .has_arg = 1,  .flag = 0,  .val = 'I'},
    {.name = "replace",     .has_arg = 1,  .flag = 0,  .val = 'R'},
    {.name = "flush",       .has_arg = 1,  .flag = 0,  .val = 'F'},
    {.name = "default",     .has_arg = 0,  .flag = 0,  .val = 'P'},
    {.name = "src",         .has_arg = 1,  .flag = 0,  .val = 's'},
    {.name = "dst",         .has_arg = 1,  .flag = 0,  .val = 'd'},
    {.name = "proto",       .has_arg = 1,  .flag = 0,  .val = OPTION_PROTO},
    {.name = "sport",       .has_arg = 1,  .flag = 0,  .val = OPTION_SPORT},
    {.name = "dport",       .has_arg = 1,  .flag = 0,  .val = OPTION_DPORT},
    {.name = "action",      .has_arg = 1,  .flag = 0,  .val = OPTION_ACTION},
    {.name = "encrypt",     .has_arg = 0,  .flag = 0,  .val = OPTION_ENCRYPT},
    {.name = "compress",    .has_arg = 0,  .flag = 0,  .val = OPTION_COMPRESS},
    {.name = "duplicate",   .has_arg = 0,  .flag = 0,  .val = OPTION_DUPLICATE},
    {.name = "multipath",   .has_arg = 0,  .flag = 0,  .val = OPTION_MULTIPATH},
    {.name = "retx",        .has_arg = 0,  .flag = 0,  .val = OPTION_RETX},
    {.name = "link-select", .has_arg = 1,  .flag = 0,  .val = 'm'},
    {.name = "priority",    .has_arg = 1,  .flag = 0,  .val = 'p'},
    {.name = "rate-limit",  .has_arg = 1,  .flag = 0,  .val = 'l'}, // bandwidth to limit to
    {.name = "help",        .has_arg = 0,  .flag = 0,  .val = 'h'},  //also add ?
    {.name = 0,             .has_arg = 0,  .flag = 0,  .val =  0},
};

const char* optstring = "LA:D:I:R:F:P:s:d:m:p:l:h";

static void usage(const char *cmd)
{
    printf("Usage: %s -[LADIF] <table> <specification>\n", cmd);
    printf("       %s -I <table> <position> <specification>\n", cmd);
    printf("\n");
    printf("Commands: \n");
    printf("  --list     -L    List active policies.\n");
    printf("  --append   -A    Append a policy to the table.\n");
    printf("  --delete   -D    Delete a policy.\n");
    printf("  --insert   -I    Insert a policy at the given position.\n");
    printf("  --flush    -F    Flush the policy table.\n");
    printf("\n");
    printf("Table names:\n");
    printf("  INPUT | OUTPUT | ALL\n");
    printf("\n");
    printf("Specification:\n");
    printf("  --src address[/mask]\n");
    printf("  --dst address[/mask]\n");
    printf("  --proto TCP|UDP|ICMP\n");
    printf("  --sport port\n");
    printf("  --dport port\n");
    printf("  --action PASS|NAT|ENCAP|DECAP|LISP|DROP\n");
    printf("  --link-select rr|wrr|dynamic|random|first\n"); //TODO
//    printf("  --priority HIGH|LOW\n");
//    printf("  --rate-limit device rate\n");
//    printf("  --encrypt\n");
//    printf("  --compress\n");
    printf("  --duplicate\n");
    printf("  --multipath\n");
    printf("  --retx           EXPERIMENTAL: May cause excessive traffic.\n");
}


static void print_version(void)
{
    printf("%s\n", version);
}



unsigned int inet_str_to_hex(char *str)
{
    struct in_addr sa;
    inet_pton(AF_INET, str, &sa);
    return sa.s_addr;
}

void print_policy_str(char *str)
{
    //printf("%s\n", str);
}

uint32_t slash_to_netmask(unsigned slash)
{
    if(slash == 0)
        return 0;
    else if(slash >= 32)
        return 0xFFFFFFFF;
    else
        return htonl(~((1 << (32 - slash)) - 1));
}

unsigned netmask_to_slash(uint32_t netmask)
{
    if(netmask == 0)
        return 0;
    else if(netmask == 0xFFFFFFFF)
        return 32;
    else
        return 32 - log2(~ntohl(netmask) + 1);
}


int main(int argc, char *argv[])
{
    // kernel: policy_mode policy_type policy_mask netaddr netmask proto port device_list
    // user: policy mode type flow_info policy_list/flags
    //
    // check that there is only one route policy
    // check that addresses are ok
    //  -host www.google.com -> convert to address/network for each slave
    //     ** could also play a trick when we see the DNS responce come back and load a policy then
    //  -app skype/firefox -> convert to PID
    //  -app foreground/background -> push current active PID down
    //  -dev wlan0/eth0/ppp0 -> pass device number down?
    //  -location home/work??? TODO

    struct policy_req policy = {
        .type = POLICY_TYPE_FLOW,
        .row = -1,
        .net_proto = 0,
        .src_netmask = 0,
        .dst_netmask = 0,
        .proto = 0,
        .src_port = 0,
        .dst_port = 0,
    };

    //int is_tc_policy = 0;

    int longindex = 0;
    int c;
    int result;

    c = getopt_long(argc, argv, optstring, longopts, &longindex);
    while(c != -1) {
        switch(c) {
            case 'L':
                return list_policies();
            case 'A':
                policy.command = POLICY_CMD_APPEND;
                optind = parse_policy_table(argc, argv, optind, &policy);
                if(!optind) {
                    printf("Unrecognized policy type: %s\n", optarg);
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case 'D':
                policy.command = POLICY_CMD_DELETE;
                optind = parse_policy_table(argc, argv, optind, &policy);
                if(!optind) {
                    printf("Unrecognized policy type: %s\n", optarg);
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case 'I':
                policy.command = POLICY_CMD_INSERT;
                optind = parse_policy_table(argc, argv, optind, &policy);
                if(!optind) {
                    printf("Unrecognized policy type: %s\n", optarg);
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case 'R':
                policy.command = POLICY_CMD_REPLACE;
                optind = parse_policy_table(argc, argv, optind, &policy);
                if(!optind) {
                    printf("Unrecognized policy type: %s\n", optarg);
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case 'F':
                policy.command = POLICY_CMD_FLUSH;
                optind = parse_policy_table(argc, argv, optind, &policy);
                if(!optind) {
                    printf("Unrecognized policy type: %s\n", optarg);
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case 'P':
                // default policy
                policy.command = POLICY_CMD_APPEND;
                policy.type = POLICY_TYPE_DEFAULT;
                //if(!parse_policy_type("default", &policy)) {
                //if(!( optind = parse_policy_table(argc, argv, optind, &policy)) ) {
                //    printf("ERROR: policy syntax error.\n");
                //    usage(argv[0]);
                //    exit(1);
                //}
                break;
            case 'f':
                // only valid for flow policies
                policy.type = POLICY_TYPE_FLOW;
                flag_tuple++;
                break;
            case 's':
                // source address
                result = parse_address(optarg, &policy, SOURCE);
                if(result < 0) {
                    printf("ERROR: invalid source address.\n");
                    usage(argv[0]);
                    exit(1);
                }
                flag_src_tuple++;
                break;
            case 'd':
                // dest address
                result = parse_address(optarg, &policy, DEST);
                if(result < 0) {
                    printf("ERROR: invalid destination address.\n");
                    usage(argv[0]);
                    exit(1);
                }
                flag_dst_tuple++;
                break;
            case OPTION_PROTO:
                result = parse_protocol(optarg, &policy);
                if(result < 0) {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case OPTION_SPORT:
                result = parse_port(optarg, &policy, SOURCE);
                if(result < 0) {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case OPTION_DPORT:
                result = parse_port(optarg, &policy, DEST);
                if(result < 0) {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            case OPTION_ACTION:
                result = parse_action(optarg, &policy);
                if(result < 0) {
                    usage(argv[0]);
                    exit(1);
                }
                flag_route++;
                break;
            case OPTION_ENCRYPT:
                policy.action |= POLICY_OP_ENCRYPT;
                break;
            case OPTION_COMPRESS:
                policy.action |= POLICY_OP_COMPRESS;
                break;
            case OPTION_DUPLICATE:
                policy.action |= POLICY_OP_DUPLICATE;
                break;
            case OPTION_MULTIPATH:
                policy.action |= POLICY_OP_MULTIPATH;
                break;
            case OPTION_RETX:
                policy.action |= POLICY_OP_RETX;
                break;
            case 'm':
                result = parse_link_select(optarg, &policy);
                if(result < 0) {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            /*case 'p':
                printf("found priority command\n");
                if( !(optind = parse_priority(argc, argv, optind)) ) {
                    printf("ERROR: invalid priority parameter(s).\n");
                    usage(argv[0]);
                    exit(1);
                }
                is_tc_policy = 1;
                break;
            case 'l':
                // rate limit
                if( !(optind = parse_ratelimit(argc, argv, optind)) ) {
                    printf("ERROR: invalid rate limit parameter(s).\n");
                    usage(argv[0]);
                    exit(1);
                }
                is_tc_policy = 1;
                break;*/
            case 'h':
            default:
                print_version();
                usage(argv[0]);
                exit(0);
        }

        c = getopt_long(argc, argv, optstring, longopts, &longindex);
    }

    /*if( is_tc_policy == 1 ) {
        // handle here and return
        struct tc_flow_tuple tuple;
        tuple.proto = policy.proto;
        tuple.src_mask = policy.src_netmask;
        tuple.ipv4_src = policy.src_addr;
        tuple.port_src = policy.src_port;
        tuple.dst_mask = policy.dst_netmask;
        tuple.ipv4_dst = policy.dst_addr;
        tuple.port_dst = policy.dst_port;

        tc_action type = 0;
        if( policy.command == POLICY_CMD_APPEND ) {
            type = TC_ADD;
        } else if( policy.command == POLICY_CMD_INSERT ) {
            type = TC_ADD;
        } else if( policy.command == POLICY_CMD_DELETE ) {
            type = TC_DEL;
        } else if( policy.command == POLICY_CMD_REPLACE ) {
            type = TC_CHANGE;
        } else {
            // unknown state
        }

        int rtn = tc_policy(&tuple, type);
        return rtn;
    }*/



    //printf("policy mask is: 0x%03x\n", policy.mask);

/*
    if( !check_policy_for_conflicts(&policy) ) {
        printf("ERROR: conflicts were detected.\n");
        exit(1);
    }
*/

    /* Check that the action is defined for commands that create a new policy. */
    switch(policy.command) {
        case POLICY_CMD_APPEND:
        case POLICY_CMD_INSERT:
        case POLICY_CMD_REPLACE:
            if((policy.action & 0xF) == 0) {
                printf("Error: action (NAT, ENCAP, etc.) must be included in policy specification.\n");
                printf("\n");
                usage(argv[0]);
                exit(1);
            }
    }

    // copy to the kernel
    int sockfd = 0;

    if( (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0 ) {
        printf("ERROR: connecting to policy framework.\n");
        exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    char *master = "virt0";
    strncpy(ifr.ifr_name, master, sizeof(ifr.ifr_name));
    ifr.ifr_data = &policy;

    if( ioctl(sockfd, SIOCVIRTSETPOLICY, &ifr) < 0 ) {
        perror("Copying policy to kernel failed");
    }

    close(sockfd);

    return 0;
}

static int parse_policy_table(int argc, char *argv[], int index, struct policy_req *policy)
{
    int row = POLICY_ROW_NONE;

    index--;
    if(!strcasecmp(argv[index], "all")) {
        policy->table = POLICY_TBL_INPUT | POLICY_TBL_OUTPUT;
    } else if(!strcasecmp(argv[index], "input")) {
        policy->table = POLICY_TBL_INPUT;
    } else if(!strcasecmp(argv[index], "output")) {
        policy->table = POLICY_TBL_OUTPUT;
    } else {
        printf("Invalid table was specified: %s.\n", argv[index]);
        return 0;
    }

    index++;

    if(index < argc && isdigit(argv[index][0])) {
        row = atoi(argv[index++]);

        if(row <= 0) {
            fprintf(stderr, "Invalid policy number (%d), must be greater than zero.\n", row);
            return 0;
        }
    }

    /* Kernel code starts the table at zero. */
    policy->row = row - 1;

    return index;
}

/*
static int parse_ratelimit(int argc, char *argv[], int index, struct policy_req *policy)
{
    //adjust index
    index--;

    if( !argv[index] )
        return 0;

    // must be associated with a src/dst tuple (i.e., only flow policies)
    //printf("rate limit set to: %d\n", atoi(argv[index]));

    // policy->max_rate = atoi(argv[index]);
    return 1;
}
*/


static int parse_address(char *arg, struct policy_req *policy, int type)
{
    char *tok;
    unsigned addr;
    unsigned mask;
    
    tok = strtok(arg, "/");
    if(!tok || inet_pton(AF_INET, tok, (struct in_addr *)&addr) <= 0) {
        addr = 0;
    }

    tok = strtok(0, "/");
    if(!tok) {
        mask = 0xFFFFFFFF;
    } else if(inet_pton(AF_INET, tok, (struct in_addr *)&mask) <= 0) {
        int slash = atoi(tok);
        if(slash >= 0 && slash <= 32) {
            mask = slash_to_netmask(slash);
        } else {
            printf("Invalid netmask or slash notation: %s\n", tok);
            return -1;
        }
    }

    if(type == SOURCE) {
        policy->src_addr = addr;
        policy->src_netmask = mask;
    } else {
        policy->dst_addr = addr;
        policy->dst_netmask = mask;
    }
    
    return 0;
}

static int parse_protocol(char *arg, struct policy_req *policy)
{
    if(!strcasecmp(arg, "tcp")) {
        policy->proto = IPPROTO_TCP;
    } else if(!strcasecmp(arg, "udp")) {
        policy->proto = IPPROTO_UDP;
    } else if(!strcasecmp(arg, "icmp")) {
        policy->proto = IPPROTO_ICMP;
    } else if(isdigit(arg[0])) {
        int tmp = atoi(arg);
        if(tmp < IPPROTO_MAX) {
            policy->proto = tmp;
        } else {
            printf("Invalid protocol: %s\n", arg);
            return -1;
        }
    } else {
        printf("Unrecognized protocol: %s\n", arg);
        return -1;
    }

    return 0;
}

static int parse_port(char *arg, struct policy_req *policy, int type)
{
    int port = atoi(arg);
    if(port < 0 || port > 0x0000FFFF) {
        printf("Invalid port: %s\n", arg);
        return -1;
    }

    if(type == SOURCE) {
        policy->src_port = htons(port);
    } else {
        policy->dst_port = htons(port);
    }

    return 0;
}

static int parse_action(char *arg, struct policy_req *policy)
{
    unsigned new_action = 0;

    if(!strcasecmp(arg, "pass")) {
        new_action = POLICY_ACT_PASS;
    } else if(!strcasecmp(arg, "nat")) {
        new_action = POLICY_ACT_NAT;
    } else if(!strcasecmp(arg, "encap")) {
        new_action = POLICY_ACT_ENCAP;
    } else if(!strcasecmp(arg, "decap")) {
        new_action = POLICY_ACT_DECAP;
    } else if(!strcasecmp(arg, "lisp")) {
        new_action = POLICY_ACT_LISP;
    } else if(!strcasecmp(arg, "drop")) {
        new_action = POLICY_ACT_DROP;
    } else {
        printf("Unrecognized action: %s\n", arg);
        return -1;
    }

    policy->action = (policy->action & ~POLICY_ACT_MASK) | new_action;
    
    return 0;
}

static int parse_link_select(char *arg, struct policy_req *policy)
{
    char *tok;

    tok = strtok(arg, ":");

    if(!strcasecmp(tok, "static")) {
        tok = strtok(0, "/");
        if(!tok) {
            printf("Static link selection requires a list of interfaces.\n");
            return -1;
        }

        // TODO parse interface list
    } else if(!strcasecmp(tok, "dynamic")) {
        tok = strtok(0, "/");
        if(!tok) {
            strncpy(policy->alg_name, "dynamic", sizeof(policy->alg_name));
        } else if(!strcasecmp(tok, "reassign")) {
            strncpy(policy->alg_name, "dynamic", sizeof(policy->alg_name));
        } else if(!strcasecmp(tok, "multi")) {
            strncpy(policy->alg_name, "dynamic_multi", sizeof(policy->alg_name));
        } else {
            printf("Unrecognized option for dynamic link selection: %s\n", tok);
            return -1;
        }
    } else if(!strcasecmp(tok, "random")) {
        strncpy(policy->alg_name, "random", sizeof(policy->alg_name));
    } else if(!strcasecmp(tok, "first")) {
        strncpy(policy->alg_name, "first", sizeof(policy->alg_name));
    } else if(!strcasecmp(tok, "wrr")) {
        strncpy(policy->alg_name, "wrr", sizeof(policy->alg_name));
    } else if(!strcasecmp(tok, "rr")) {
        strncpy(policy->alg_name, "rr", sizeof(policy->alg_name));
    } else {
        printf("Unrecognized link selection algorithm: %s\n", tok);
        return -1;
    }

    return 0;
}

static int check_policy_for_conflicts(struct policy_req *policy)
{
    // check tuple dependencies
    if( policy->type == POLICY_TYPE_FLOW ) {
        if( !(flag_src_tuple) && !(flag_dst_tuple) ) {
            // flow policies need at least one tuple defined
            printf("ERROR: flow policies need a tuple defined.\n");
            return 0;
        }
    } else if( policy->type == POLICY_TYPE_APP ) {
        if( flag_tuple ) {
            // application policies cannot have tuples defined
            printf("ERROR: application policies should not define a tuple.\n");
            return 0;
        }
    } else if( policy->type == POLICY_TYPE_DEV ) {
        if( flag_tuple ) {
            // device policies cannot have tuples defined
            printf("ERROR: application policies should not define a tuple.\n");
            return 0;
        }
    } else if( policy->type == POLICY_TYPE_DEFAULT ) {
        if( !flag_route ) {
            //default needs to specify some type of route
            printf("ERROR: default policy needs to specify some type of policy.\n");
            return 0;
        }
    }

    // should only have one flow,app,or dev policy


    return 1;
}
        

const char *ACTION_STRINGS[16] = {
    [0]                = "NULL",
    [POLICY_ACT_PASS]  = "PASS",
    [POLICY_ACT_NAT]   = "NAT",
    [POLICY_ACT_ENCAP] = "ENCAP",
    [POLICY_ACT_DECAP] = "DECAP",
    [POLICY_ACT_LISP]  = "LISP",
    [POLICY_ACT_DROP]  = "DROP",
};

static int print_nice_policy_line(char *buffer)
{
    unsigned src_ip;
    char src_addr[INET_ADDRSTRLEN];
    int src_net;
    unsigned dst_ip;
    char dst_addr[INET_ADDRSTRLEN];
    int dst_net;
    char proto[8];
    unsigned short src_port;
    unsigned short dst_port;

    const char *action;
    int action_code;
    int options;
    char *link_select;

    unsigned long rxpkts;
    unsigned long txpkts;
    unsigned long rxbytes;
    unsigned long txbytes;

    char *token;
    unsigned tmp;

    /* Source address */
    token = strtok(buffer, " ");
    if(!token)
        return -1;
    src_ip = strtoul(token, NULL, 16);
    inet_ntop(AF_INET, &src_ip, src_addr, sizeof(src_addr));

    /* Source netmask */
    token = strtok(NULL, " ");
    if(!token)
        return -1;
    tmp = strtoul(token, NULL, 16);
    src_net = netmask_to_slash(tmp);

    /* Destination address */
    token = strtok(NULL, " ");
    if(!token)
        return -1;
    dst_ip = strtoul(token, NULL, 16);
    inet_ntop(AF_INET, &dst_ip, dst_addr, sizeof(dst_addr));

    /* Destination netmask */
    token = strtok(NULL, " ");
    if(!token)
        return -1;
    tmp = strtoul(token, NULL, 16);
    dst_net = netmask_to_slash(tmp);
    
    token = strtok(NULL, " ");
    if(!token)
        return -1;
    tmp = strtoul(token, NULL, 16);
    switch(tmp) {
        case 0:
            strncpy(proto, "*", sizeof(proto));
            break;
        case IPPROTO_ICMP:
            strncpy(proto, "ICMP", sizeof(proto));
            break;
        case IPPROTO_TCP:
            strncpy(proto, "TCP", sizeof(proto));
            break;
        case IPPROTO_UDP:
            strncpy(proto, "UDP", sizeof(proto));
            break;
        default:
            snprintf(proto, sizeof(proto), "%hu", tmp);
            break;
    }

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    src_port = ntohs((unsigned short)strtoul(token, NULL, 16));

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    dst_port = ntohs((unsigned short)strtoul(token, NULL, 16));

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    tmp = strtoul(token, NULL, 16);

    action_code = tmp & 0xF;
    action = ACTION_STRINGS[action_code];
    options = tmp & (~0xF);
    
    token = strtok(NULL, " ");
    if(!token)
        return -1;

    if(options & POLICY_OP_MULTIPATH)
        link_select = "multipath";
    else if(options & POLICY_OP_DUPLICATE)
        link_select = "duplicate";
    else if(action_code == POLICY_ACT_PASS ||
            action_code == POLICY_ACT_NAT || 
            action_code == POLICY_ACT_ENCAP)
        link_select = token;
    else
        link_select = "-";

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    /* skip refcnt */

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    rxpkts = strtoul(token, NULL, 10);

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    txpkts = strtoul(token, NULL, 10);

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    rxbytes = strtoul(token, NULL, 10);

    token = strtok(NULL, " ");
    if(!token)
        return -1;
    txbytes = strtoul(token, NULL, 10);

    char src_net_str[INET_ADDRSTRLEN + 3];
    if(src_net > 0 && src_net < 32)
        snprintf(src_net_str, sizeof(src_net_str), "%s/%d", src_addr, src_net);
    else
        strncpy(src_net_str, src_addr, sizeof(src_net_str));
    
    char dst_net_str[INET_ADDRSTRLEN + 3];
    if(dst_net > 0 && dst_net < 32)
        snprintf(dst_net_str, sizeof(dst_net_str), "%s/%d", dst_addr, dst_net);
    else
        strncpy(dst_net_str, dst_addr, sizeof(dst_net_str));

    char src_port_str[6];
    if(src_port)
        snprintf(src_port_str, sizeof(src_port_str), "%hu", src_port);
    else
        strncpy(src_port_str, "*", sizeof(src_port_str));
    
    char dst_port_str[6];
    if(dst_port)
        snprintf(dst_port_str, sizeof(dst_port_str), "%hu", dst_port);
    else
        strncpy(dst_port_str, "*", sizeof(dst_port_str));

    printf("%-18s %-18s %-4s %-5s %-5s %-5s %-10s %7lu %10lu\n",
            src_net_str,
            dst_net_str,
            proto,
            src_port_str,
            dst_port_str,
            action,
            link_select,
            rxpkts + txpkts,
            rxbytes + txbytes);

    return 0;
}

static int list_policies()
{
    FILE *file = fopen("/proc/virtmod/policy/policy_v4", "r");
    if(!file) {
        fprintf(stderr, "Failed to open policy table, is virtNet module loaded?\n");
        return 1;
    }

    char buffer[BUFSIZ];

    /*     "ssssssssssssssssss dddddddddddddddddd pppp sssss ddddd aaaaa llllllllll ppppppp bbbbbbbbbb" */
    printf("EGRESS policy table\n");
    printf("source             destination        prot sport dport actn  linkselect packets      bytes\n");

    /* First read EGRESS table */
    while(!feof(file)) {
        fgets(buffer, sizeof(buffer), file);

        if(strncasecmp(buffer, "egress", 6) == 0) {
            continue;
        } else if(strncasecmp(buffer, "source", 6) == 0) {
            continue;
        } else if(strncasecmp(buffer, "ingress", 7) == 0) {
            break;
        }

        print_nice_policy_line(buffer);
    }

    printf("\n");
    
    /*     "ssssssssssssssssss dddddddddddddddddd pppp sssss ddddd aaaaa llllllllll ppppppp bbbbbbbbbb" */
    printf("INGRESS policy table\n");
    printf("source             destination        prot sport dport actn  linkselect packets      bytes\n");
    
    /* Next read INGRESS table */
    while(!feof(file)) {
        fgets(buffer, sizeof(buffer), file);

        if(strncasecmp(buffer, "source", 6) == 0) {
            continue;
        }

        print_nice_policy_line(buffer);
    }

    fclose(file);

    return 0;
}


