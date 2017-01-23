#ifndef _QUAGGA_BGP_FLOWSPEC_H
#define _QUAGGA_BGP_FLOWSPC_H
//#define MY_IMPLEMENT 0

/* Flowspec raffic action bit*/
#define	FLOWSPEC_TRAFFIC_ACTION_TERMINAL	0
#define FLOWSPEC_TRAFFIC_ACTION_SAMPLE		1	
#define FLOWSPEC_TRAFFIC_ACTION_DISTRIBUTE	2	

/* Flow Spec Operator bit set*/
#define FLOWSPEC_OPERATOR_EQUALL	1
#define FLOWSPEC_OPERATOR_GREATER	(1 << 1)
#define FLOWSPEC_OPERATOR_LESS		(1 << 2)
#define FLOWSPEC_OPERATOR_GE		(FLOWSPEC_OPERATOR_GREATER|FLOWSPEC_OPERATOR_EQUALL)
#define FLOWSPEC_OPERATOR_LE		(FLOWSPEC_OPERATOR_LESS|FLOWSPEC_OPERATOR_EQUALL)
#define FLOWSPEC_OPERATOR_AND		(1 << 6)
#define FLOWSPEC_OPERATOR_END		(1 << 7)

#define FLOWSPEC_OPERAND_MATCH		(1 << 0)

#define MAX_FLOWSEC_NLRI_LEN	4095

/* Flow Spec Component Types */
#define NUM_OF_FLOWSPEC_MATCH_TYPES 12
#define	FLOWSPEC_DEST_PREFIX	1
#define	FLOWSPEC_SRC_PREFIX		2
#define	FLOWSPEC_IP_PROTOCOL	3
#define	FLOWSPEC_PORT			4
#define FLOWSPEC_DEST_PORT		5
#define FLOWSPEC_SRC_PORT		6
#define FLOWSPEC_ICMP_TYPE		7
#define FLOWSPEC_ICMP_CODE		8
#define FLOWSPEC_TCP_FLAGS		9
#define FLOWSPEC_PKT_LEN		10
#define FLOWSPEC_DSCP			11
#define FLOWSPEC_FRAGMENT		12
#if 0
struct rule_prefix_head
{
	struct prefix p;
	struct rule_prefix_head *next_rule;
};
/**/
struct rule_node
{
	struct rule_node *next_node;
	int value; // value or bitmask
	int operator; // less than is 2; larger than is 1; equall to is 0;
};

struct rule_head
{
	struct rule_node *node;
	struct rule_head *next_rule;
};

struct flowspec_rule
{
	struct rule_prefix_head *dest_prefix;
	struct rule_prefix_head *src_prefix;
	struct rule_head *ip_protocol;
	struct rule_head *port;
	struct rule_head *dest_port;
	struct rule_head *src_port;
	struct rule_head *icmp_type;
	struct rule_head *icmp_code;
	struct rule_head *tcp_flags;
	struct rule_head *pkt_len;
	struct rule_head *dscp;
	struct rule_head *fragment;
};
#else
/* Route map's type. */
enum flowspec_type
{
  FLOWSPEC_PERMIT,
  FLOWSPEC_DENY,
  FLOWSPEC_ANY
};

typedef enum 
{
  FLOWSPEC_MATCH,
  FLOWSPEC_DENYMATCH,
  FLOWSPEC_NOMATCH,
  FLOWSPEC_ERROR,
  FLOWSPEC_OKAY
} flowspec_result_t;

typedef enum
{
  FLOWSPEC_RIP,
  FLOWSPEC_RIPNG,
  FLOWSPEC_BABEL,
  FLOWSPEC_OSPF,
  FLOWSPEC_OSPF6,
  FLOWSPEC_BGP,
  FLOWSPEC_ZEBRA,
  FLOWSPEC_ISIS,
} flowspec_object_t;

typedef enum
{
  FLOWSPEC_EXIT,
  FLOWSPEC_GOTO,
  FLOWSPEC_NEXT
} flowspec_end_t;

typedef enum
{
  FLOWSPEC_EVENT_SET_ADDED,
  FLOWSPEC_EVENT_SET_DELETED,
  FLOWSPEC_EVENT_SET_REPLACED,
  FLOWSPEC_EVENT_MATCH_ADDED,
  FLOWSPEC_EVENT_MATCH_DELETED,
  FLOWSPEC_EVENT_MATCH_REPLACED,
  FLOWSPEC_EVENT_INDEX_ADDED,
  FLOWSPEC_EVENT_INDEX_DELETED
} flowspec_event_t;

/* Route map rule structure for matching and setting. */
struct flowspec_rule_cmd
{
  /* Route map rule name (e.g. as-path, metric) */
  const char *str;

  /* Function for value set or match. */
  flowspec_result_t (*func_apply)(void *, struct prefix *, 
				   flowspec_object_t, void *);

  /* Compile argument and return result as void *. */
  void *(*func_compile)(const char *);

  /* Free allocated value by func_compile (). */
  void (*func_free)(void *);

  /* flowspec match or set type */
  u_int8_t type;
};
#if 0
/* Route map apply error. */
enum
{
  /* Route map rule is missing. */
  FLOWSPEC_RULE_MISSING = 1,

  /* Route map rule can't compile */
  FLOWSPEC_COMPILE_ERROR
};
#endif

/* Route map rule list. */
struct flowspec_rule_list
{
  struct flowspec_rule *head;
  struct flowspec_rule *tail;
};

/* Route map index structure. */
struct flowspec_index
{
  struct flowspec *map;
  char *description;

  /* Preference of this route map rule. */
  int pref;

  /* Route map type permit or deny. */
  enum flowspec_type type;			

  /* Do we follow old rules, or hop forward? */
  flowspec_end_t exitpolicy;

  /* If we're using "GOTO", to where do we go? */
  int nextpref;

  /* If we're using "CALL", to which route-map do ew go? */
  char *nextrm;

  /* Matching rule list. */
  struct flowspec_rule_list match_list[NUM_OF_FLOWSPEC_MATCH_TYPES];
  struct flowspec_rule_list set_list;
  
  /* Make linked list. */
  struct flowspec_index *next;
  struct flowspec_index *prev;
};

/* Route map list structure. */
struct flowspec
{
  /* Name of route map. */
  char *name;

  /* Route map's rule. */
  struct flowspec_index *head;
  struct flowspec_index *tail;

  /* Make linked list. */
  struct flowspec *next;
  struct flowspec *prev;
};
#endif

/* Route map apply error. */
enum
{
  /* Route map rule is missing. */
  FLOWSPEC_RULE_MISSING = 1,

  /* Route map rule can't compile */
  FLOWSPEC_COMPILE_ERROR
};

extern int
encode_flowspec_nlri (struct flowspec_index *index, u_int8_t *nlri_str);

extern struct flowspec_index *
flowspec_index_lookup (struct flowspec *map, enum flowspec_type type,
			int pref);

extern void bgp_flowspec_init (void);

extern int
encode_flowspec_set (struct flowspec_index *index, u_int8_t *action_str, as_t as);

extern int
encode_flowspec_match (struct flowspec_index *index, u_int8_t *nlri_str);

extern struct flowspec *
flowspec_lookup_by_name (const char *name);
#endif /* _QUAGGA_BGP_FLOWSPEC_H */

