#include <zebra.h>

#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "vector.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_flowspec.h"

//char operator_char[3] = {'=','>','<'};

/* Vector for route match rules. */
static vector flowspec_match_vec;

/* Vector for route set rules. */
static vector flowspec_set_vec;

/* Install rule command to the match list. */
static void
flowspec_install_match (struct flowspec_rule_cmd *cmd)
{
  vector_set (flowspec_match_vec, cmd);
}

/* Install rule command to the set list. */
static void
flowspec_install_set (struct flowspec_rule_cmd *cmd)
{
  vector_set (flowspec_set_vec, cmd);
}

/* Route map rule. This rule has both `match' rule and `set' rule. */
struct flowspec_rule
{
  /* Rule type. */
  struct flowspec_rule_cmd *cmd;

  /* For pretty printing. */
  char *rule_str;

  /* Pre-compiled match rule. */
  void *value;

  /* Linked list. */
  struct flowspec_rule *next;
  struct flowspec_rule *prev;

  // less than is 2; larger than is 1; equall to is 0;
  // u_int8_t operator;
};

/* Making route map list. */
struct flowspec_list
{
  struct flowspec *head;
  struct flowspec *tail;

  void (*add_hook) (const char *);
  void (*delete_hook) (const char *);
  void (*event_hook) (flowspec_event_t, const char *); 
};

/* Master list of route map. */
static struct flowspec_list flowspec_master = { NULL, NULL, NULL, NULL };

/* Route map node structure. */
static struct cmd_node fs_node =
{
  FLOWSPEC_NODE,
  "%s(config-flowspec)# ",
  1
};

struct ecom_content
{
	u_int8_t val[6];
};

/* Delete rule from rule list. */
static void
flowspec_rule_delete (struct flowspec_rule_list *list,
		       struct flowspec_rule *rule)
{
#if 1
  if (rule->cmd->func_free)
    (*rule->cmd->func_free) (rule->value);
#endif
	printf("**********func_free\n");
  if (rule->rule_str)
    XFREE (MTYPE_FLOWSPEC_RULE_STR, rule->rule_str);

  if (rule->next)
    rule->next->prev = rule->prev;
  else
    list->tail = rule->prev;
  if (rule->prev)
    rule->prev->next = rule->next;
  else
    list->head = rule->next;

  XFREE (MTYPE_FLOWSPEC_RULE, rule);
}

/* New route map allocation. Please note route map's name must be
   specified. */
static struct flowspec_index *
flowspec_index_new (void)
{
  struct flowspec_index *new;

  new =  XCALLOC (MTYPE_FLOWSPEC_INDEX, sizeof (struct flowspec_index));
  new->exitpolicy = FLOWSPEC_EXIT; /* Default to Cisco-style */
  return new;
}

/* Free route map index. */
static void
flowspec_index_delete (struct flowspec_index *index, int notify)
{
  struct flowspec_rule *rule;

  /* Free route match. */
  while ((rule = index->match_list[0].head) != NULL)
    flowspec_rule_delete (&index->match_list[0], rule);

  /* Free route set. */
  while ((rule = index->set_list.head) != NULL)
    flowspec_rule_delete (&index->set_list, rule);

  /* Remove index from route map list. */
  if (index->next)
    index->next->prev = index->prev;
  else
    index->map->tail = index->prev;

  if (index->prev)
    index->prev->next = index->next;
  else
    index->map->head = index->next;

  /* Free 'char *nextrm' if not NULL */
  if (index->nextrm)
    XFREE (MTYPE_FLOWSPEC_NAME, index->nextrm);

    /* Execute event hook. */
  if (flowspec_master.event_hook && notify)
    (*flowspec_master.event_hook) (FLOWSPEC_EVENT_INDEX_DELETED,
				    index->map->name);

  XFREE (MTYPE_FLOWSPEC_INDEX, index);
}

/* Lookup index from route map. */
// static struct flowspec_index *
struct flowspec_index *
flowspec_index_lookup (struct flowspec *map, enum flowspec_type type,
			int pref)
{
  struct flowspec_index *index;

  for (index = map->head; index; index = index->next)
    if ((index->type == type || type == FLOWSPEC_ANY)
	&& index->pref == pref)
      return index;
  return NULL;
}

/* Add new index to route map. */
static struct flowspec_index *
flowspec_index_add (struct flowspec *map, enum flowspec_type type,
		     int pref)
{
  struct flowspec_index *index;
  struct flowspec_index *point;

  /* Allocate new route map inex. */
  index = flowspec_index_new ();
  index->map = map;
  index->type = type;
  index->pref = pref;
  
  /* Compare preference. */
  for (point = map->head; point; point = point->next)
    if (point->pref >= pref)
      break;

  if (map->head == NULL)
    {
      map->head = map->tail = index;
    }
  else if (point == NULL)
    {
      index->prev = map->tail;
      map->tail->next = index;
      map->tail = index;
    }
  else if (point == map->head)
    {
      index->next = map->head;
      map->head->prev = index;
      map->head = index;
    }
  else
    {
      index->next = point;
      index->prev = point->prev;
      if (point->prev)
	point->prev->next = index;
      point->prev = index;
    }

  /* Execute event hook. */
  if (flowspec_master.event_hook)
    (*flowspec_master.event_hook) (FLOWSPEC_EVENT_INDEX_ADDED,
				    map->name);

  return index;
}

/* Get route map index. */
static struct flowspec_index *
flowspec_index_get (struct flowspec *map, enum flowspec_type type, 
		     int pref)
{
  struct flowspec_index *index;

  index = flowspec_index_lookup (map, FLOWSPEC_ANY, pref);
  if (index && index->type != type)
    {
      /* Delete index from route map. */
      flowspec_index_delete (index, 1);
      index = NULL;
    }
  if (index == NULL)
    index = flowspec_index_add (map, type, pref);
  return index;
}

/* Lookup route map by route map name string. */
struct flowspec *
flowspec_lookup_by_name (const char *name)
{
  struct flowspec *map;

  for (map = flowspec_master.head; map; map = map->next)
    if (strcmp (map->name, name) == 0)
      return map;
  return NULL;
}

/* New route map allocation. Please note route map's name must be
   specified. */
static struct flowspec *
flowspec_new (const char *name)
{
  struct flowspec *new;

  new =  XCALLOC (MTYPE_FLOWSPEC, sizeof (struct flowspec));
  new->name = XSTRDUP (MTYPE_FLOWSPEC_NAME, name);
  return new;
}

/* Add new name to route_map. */
static struct flowspec *
flowspec_add (const char *name)
{
  struct flowspec *map;
  struct flowspec_list *list;

  map = flowspec_new (name);
  list = &flowspec_master;
    
  map->next = NULL;
  map->prev = list->tail;
  if (list->tail)
    list->tail->next = map;
  else
    list->head = map;
  list->tail = map;

  /* Execute hook. */
  if (flowspec_master.add_hook)
    (*flowspec_master.add_hook) (name);

  return map;
}

/* Lookup route map.  If there isn't route map create one and return
   it. */
static struct flowspec *
flowspec_get (const char *name)
{
  struct flowspec *map;

  map = flowspec_lookup_by_name (name);
  if (map == NULL)
    map = flowspec_add (name);
  return map;
}

/* VTY related functions. */
DEFUN (flowspec,
       flowspec_cmd,
       "flowspec WORD (deny|permit) <1-65535>",
       "Create flowspec or enter flowspec command mode\n"
       "Route map tag\n"
       "Route map denies set operations\n"
       "Route map permits set operations\n"
       "Sequence to insert to/delete from existing route-map entry\n")
{
  int permit;
  unsigned long pref;
  struct flowspec *map;
  struct flowspec_index *index;
  char *endptr = NULL;

  /* Permit check. */
  if (strncmp (argv[1], "permit", strlen (argv[1])) == 0)
    permit = FLOWSPEC_PERMIT;
  else if (strncmp (argv[1], "deny", strlen (argv[1])) == 0)
    permit = FLOWSPEC_DENY;
  else
    {
      vty_out (vty, "the third field must be [permit|deny]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Preference check. */
  pref = strtoul (argv[2], &endptr, 10);
  if (pref == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "the fourth field must be positive integer%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (pref == 0 || pref > 65535)
    {
      vty_out (vty, "the fourth field must be <1-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Get route map. */
  map = flowspec_get (argv[0]);
  index = flowspec_index_get (map, permit, pref);

  vty->index = index;
  vty->node = FLOWSPEC_NODE;
  return CMD_SUCCESS;
}

/* Lookup rule command from match list. */
static struct flowspec_rule_cmd *
flowspec_lookup_match (const char *name)
{
  unsigned int i;
  struct flowspec_rule_cmd *rule;

  for (i = 0; i < vector_active (flowspec_match_vec); i++)
    if ((rule = vector_slot (flowspec_match_vec, i)) != NULL)
      if (strcmp (rule->str, name) == 0)
	return rule;
  return NULL;
}

/* Lookup rule command from set list. */
static struct flowspec_rule_cmd *
flowspec_lookup_set (const char *name)
{
  unsigned int i;
  struct flowspec_rule_cmd *rule;

  for (i = 0; i < vector_active (flowspec_set_vec); i++)
    if ((rule = vector_slot (flowspec_set_vec, i)) != NULL)
      if (strcmp (rule->str, name) == 0)
	return rule;
  return NULL;
}

/* New route map rule */
static struct flowspec_rule *
flowspec_rule_new (void)
{
  struct flowspec_rule *new;

  new = XCALLOC (MTYPE_FLOWSPEC_RULE, sizeof (struct flowspec_rule));
  return new;
}


/* Add match and set rule to rule list. */
static void
flowspec_rule_add (struct flowspec_rule_list *list,
		    struct flowspec_rule *rule)
{
  rule->next = NULL;
  rule->prev = list->tail;
  if (list->tail)
    list->tail->next = rule;
  else
    list->head = rule;
  list->tail = rule;
}

struct fs_map_value
{
	u_int8_t operator;
	u_int32_t value;
};

/* Add match statement to route map. */
static int
flowspec_add_match (struct flowspec_index *index, const char *match_name,
                     const char *match_arg)
{
  struct flowspec_rule *rule;
  //struct flowspec_rule *next;
  struct flowspec_rule_cmd *cmd;
  void *compile;
  int replaced = 0;

  /* First lookup rule for add match statement. */
  cmd = flowspec_lookup_match (match_name);
  if (cmd == NULL)
    return FLOWSPEC_RULE_MISSING;

  /* Next call compile function for this match statement. */
  if (cmd->func_compile)
    {
      compile = (*cmd->func_compile)(match_arg);
      if (compile == NULL)
	return FLOWSPEC_COMPILE_ERROR;
    }
  else
    compile = NULL;
#if 1

  /* If argument is completely same ignore it. */
  rule = index->match_list[cmd->type-1].head;
  if((cmd->type == 1 || cmd->type == 2) && rule)
  	{
		printf("cmd->type == (1||2)\n");
		flowspec_rule_delete (&index->match_list[cmd->type-1], rule);
		//rule->value = compile;
		//if (match_arg)
		//	rule->rule_str = XSTRDUP (MTYPE_FLOWSPEC_RULE_STR, match_arg);
  	}
  	//else
  	//{
  	//printf("(%d,%d)22222222222222\n",cmd->type,index->match_list[cmd->type-1].head==NULL?0:1);
#else
  for (rule = index->match_list.head; rule; rule = next)
    {
      next = rule->next;
      if (rule->cmd == cmd)
	{	
	  flowspec_rule_delete (&index->match_list, rule);
	  replaced = 1;
	}
    }
#endif
  /* Add new route map match rule. */
  rule = flowspec_rule_new ();
  rule->cmd = cmd;
  rule->value = compile;
  if (match_arg)
    rule->rule_str = XSTRDUP (MTYPE_FLOWSPEC_RULE_STR, match_arg);
  else
    rule->rule_str = NULL;

  /* Add new route match rule to linked list. */
  //flowspec_rule_add (&index->match_list, rule);
  flowspec_rule_add (&index->match_list[cmd->type-1], rule);
  //}
  /* Execute event hook. */
  if (flowspec_master.event_hook)
    (*flowspec_master.event_hook) (replaced ?
				    FLOWSPEC_EVENT_MATCH_REPLACED:
				    FLOWSPEC_EVENT_MATCH_ADDED,
				    index->map->name);
  			    

  return 0;
}

/* Add route-map set statement to the route map. */
static int
flowspec_add_set (struct flowspec_index *index, const char *set_name,
                   const char *set_arg)
{
  struct flowspec_rule *rule;
  struct flowspec_rule *next;
  struct flowspec_rule_cmd *cmd;
  void *compile;
  int replaced = 0;

  cmd = flowspec_lookup_set (set_name);
  if (cmd == NULL)
    return FLOWSPEC_RULE_MISSING;

  /* Next call compile function for this match statement. */
  if (cmd->func_compile)
    {
      compile= (*cmd->func_compile)(set_arg);
      if (compile == NULL)
	return FLOWSPEC_COMPILE_ERROR;
    }
  else
    compile = NULL;

 /* Add by WJL. if old set command of same kind exist, delete it first
    to ensure only one set command of same kind exist under a
    route_map_index. */
  for (rule = index->set_list.head; rule; rule = next)
    {
      next = rule->next;
      if (rule->cmd == cmd)
	{
	  printf("#######flowspec_rule_delete\n");
	  flowspec_rule_delete (&index->set_list, rule);
	  replaced = 1;
	}
    }

  /* Add new route map match rule. */
  rule = flowspec_rule_new ();
  rule->cmd = cmd;
  rule->value = compile;
  if (set_arg)
    rule->rule_str = XSTRDUP (MTYPE_FLOWSPEC_RULE_STR, set_arg);
  else
    rule->rule_str = NULL;

  /* Add new route match rule to linked list. */
  flowspec_rule_add (&index->set_list, rule);

  /* Execute event hook. */
  if (flowspec_master.event_hook)
    (*flowspec_master.event_hook) (replaced ?
				    FLOWSPEC_EVENT_SET_REPLACED:
				    FLOWSPEC_EVENT_SET_ADDED,
				    index->map->name);
  return 0;
}

/* Add bgp route map rule. */
static int
show_bgp_flowspec_match (struct vty *vty, struct flowspec_index *index,
		     const char *command)
{
  struct flowspec_rule_cmd *cmd;
  struct fs_map_value *fs_match_val;
  
  cmd = flowspec_lookup_match (command);
    if (cmd == NULL)
	  return FLOWSPEC_RULE_MISSING;
  
  struct flowspec_rule *p = index->match_list[cmd->type-1].head;
  while(p)
  {
	fs_match_val = p->value;
	printf("%d ",fs_match_val->value);
	p = p->next;
  }
  printf("\n");
  return CMD_SUCCESS;
}


static int
bgp_flowspec_match_add (struct vty *vty, struct flowspec_index *index,
		     const char *command, const char *arg)
{
  int ret;
  ret = flowspec_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case FLOWSPEC_RULE_MISSING:
	  vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	case FLOWSPEC_COMPILE_ERROR:
	  vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  return CMD_SUCCESS;
}

/* Add bgp route map rule. */
static int
bgp_flowspec_set_add (struct vty *vty, struct flowspec_index *index,
		   const char *command, const char *arg)
{
  int ret;

  ret = flowspec_add_set (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case FLOWSPEC_RULE_MISSING:
	  vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	case FLOWSPEC_COMPILE_ERROR:
	  vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  return CMD_SUCCESS;
}

static void
flowspec_init (void)
{
  /* Make vector for match and set. */
  flowspec_match_vec = vector_init (1);
  flowspec_set_vec = vector_init (1);
}

static u_int8_t
bytes_of_value(u_int32_t value)
{
	u_int8_t bytes = 0;
	while((value >> (8*(++bytes))) != 0);
	return bytes;
}

static u_int8_t
convert_len_to_code(u_int8_t val_len)
{
	u_int8_t code = 0;
	while(val_len >> code != 1)
		code++;
	return code;
}

static u_int16_t
flowspec_prefix_encode(struct flowspec_rule_list *rule_list, u_int8_t *nlri, u_int8_t type)
{
	u_int16_t nlri_len = 0;
	u_int8_t count = 0;
	u_int8_t prefix_unit;
	struct prefix *p;
	struct flowspec_rule *rule = rule_list->head;
	printf("flowspec_prefix_encode\n");
	
	if(rule) 
	{
		nlri[nlri_len++] = type;
		p = rule->value;
		nlri[nlri_len++] = p->prefixlen;
		printf("p->u.prefix4.s_addr=0x%x\n",p->u.prefix4.s_addr);
		/*
		count = p->prefixlen / 8;		
		if(p->prefixlen % 8)
			count++;
		
		for(; count > 0; count--)
		{
			prefix_unit = (p->u.prefix4.s_addr >> (8 * (4-count))) & 0xff;
			nlri[nlri_len++] = prefix_unit;
			printf("prefix_unit[%d]=%d\n", count, prefix_unit);
		}*/
		if(p->prefixlen != 0)
		{
			do
			{
				prefix_unit = p->u.prefix4.s_addr >> 8*(count++);
				printf("prefix_unit[%d]=%d\n", count, prefix_unit);
				nlri[nlri_len++] = prefix_unit & 0xff;
			}while(p->u.prefix4.s_addr >> 8*count);
		}
	}
	return nlri_len;
}

static u_int16_t
flowspec_operator_encode(struct flowspec_rule_list *rule_list, u_int8_t *nlri, u_int8_t type)
{
	u_int16_t nlri_len = 0;
	u_int8_t val_len;
	u_int8_t code;
	u_int8_t count;
	u_int8_t fs_operator;
	struct fs_map_value *rule_value_node;
	struct flowspec_rule *rule = rule_list->head;

	if(rule) nlri[nlri_len++] = type;
	printf("flowspec_operator_encode\n");
	while(rule)
	{
		rule_value_node = rule->value;
		val_len = bytes_of_value(rule_value_node->value);
		printf("rule_value_node->value=%d, val_len=%d\n", rule_value_node->value, val_len);
		code = convert_len_to_code(val_len);
		/* the situation of value length is 3, the value length can only be 1,2,4,8*/
		val_len = 1 << code;
		fs_operator = (rule_value_node->operator)|(code << 4);
		if(!rule->next)
			fs_operator = fs_operator | FLOWSPEC_OPERATOR_END;		
		nlri[nlri_len++] = fs_operator;
		printf("nlri[%d]=%d\n", nlri_len-1, nlri[nlri_len-1]);
		for(count = val_len;count > 0; count--)
		{
			nlri[nlri_len++] = (rule_value_node->value >> (count-1)*8) & 0xff;
			printf("nlri[%d]=%d\n", nlri_len-1, nlri[nlri_len-1]);
		}
		rule = rule->next;
	}
	return nlri_len;
}

static u_int16_t
flowspec_bitmask_encode(struct flowspec_rule_list *rule_list, u_int8_t *nlri, u_int8_t type)
{
	u_int16_t nlri_len = 0;
	u_int8_t val_len;
	u_int8_t code;
	u_int8_t count;
	u_int8_t fs_operator;
	struct fs_map_value *rule_value_node;
	struct flowspec_rule *rule = rule_list->head;

	if(rule) nlri[nlri_len++] = type;
	printf("flowspec_bitmask_encode\n");
	while(rule)
	{
		rule_value_node = rule->value;
		val_len = bytes_of_value(rule_value_node->value);
		printf("rule_value_node->value=%d, val_len=%d\n", rule_value_node->value, val_len);
		code = convert_len_to_code(val_len);
		/* the situation of value length is 3, the value length can only be 1,2,4,8*/
		val_len = 1 << code;
		
		fs_operator = (rule_value_node->operator)|(code << 4);
		if(!rule->next)
			fs_operator = fs_operator | FLOWSPEC_OPERATOR_END;
		fs_operator = fs_operator | FLOWSPEC_OPERAND_MATCH;
		nlri[nlri_len++] = fs_operator;
		printf("nlri[%d]=%d\n", nlri_len-1, nlri[nlri_len-1]);
		for(count = val_len;count > 0; count--)
		{
			nlri[nlri_len++] = (rule_value_node->value >> (count-1)*8) & 0xff;
			printf("nlri[%d]=%d\n", nlri_len-1, nlri[nlri_len-1]);
		}
		rule = rule->next;
	}
	return nlri_len;
}

static int
bgp_show_flowspec_nlri (struct vty *vty, struct flowspec_index *index)
{
  u_int8_t type;
  u_int8_t nlri_str[MAX_FLOWSEC_NLRI_LEN];
  u_int16_t nlri_len = 0;
  //struct flowspec_rule *p;
  for(type = 1; type <= 12; type++)
  { 
	switch(type)
	{
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			nlri_len += flowspec_prefix_encode(&index->match_list[type-1], &nlri_str[nlri_len], type);
			printf("********type=%d************len=%d\n",type,nlri_len);			
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			nlri_len += flowspec_operator_encode(&index->match_list[type-1], &nlri_str[nlri_len], type);
			printf("********type=%d************len=%d\n",type,nlri_len);
			break;
		case FLOWSPEC_TCP_FLAGS:
		case FLOWSPEC_FRAGMENT:
			nlri_len += flowspec_bitmask_encode(&index->match_list[type-1], &nlri_str[nlri_len], type);
			printf("********type=%d************len=%d\n",type,nlri_len);			
			break;
		default:
				{}
	}
  }
#if 1  
  struct flowspec_rule *rule, *next;
  struct ecommunity_val *eval;
  int i,j = 0;
  for (rule = index->set_list.head; rule; rule = next)
    {
      next = rule->next;
	  eval = rule->value;
	  printf("the %d rule: ", ++j);
	  for(i = 0; i < 8; i++)
	  	printf("%u ", eval->val[i]);
	  printf("\n");
  	}
#else  
  u_int8_t tmp;
  for(tmp = 0; tmp < nlri_len; tmp++)
  {
		printf("%u ", nlri_str[tmp]);
  }
  printf("\n");
#endif
  //print_array(nlri_str, nlri_len);
  return CMD_SUCCESS;
}

int
encode_flowspec_match (struct flowspec_index *index, u_int8_t *nlri_str)
{
  u_int8_t type;
  //u_int8_t nlri_str[MAX_FLOWSEC_NLRI_LEN];
  int nlri_len = 0;
  //struct flowspec_rule *p;
  for(type = 1; type <= 12; type++)
  { 
	switch(type)
	{
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			nlri_len += flowspec_prefix_encode(&index->match_list[type-1], &nlri_str[nlri_len], type);
			//printf("********type=%d************len=%d\n",type,nlri_len);			
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			nlri_len += flowspec_operator_encode(&index->match_list[type-1], &nlri_str[nlri_len], type);
			//printf("********type=%d************len=%d\n",type,nlri_len);
			break;
		case FLOWSPEC_TCP_FLAGS:
		case FLOWSPEC_FRAGMENT:
			nlri_len += flowspec_bitmask_encode(&index->match_list[type-1], &nlri_str[nlri_len], type);			
			break;
		default:
				{}
	}
  }
  u_int8_t tmp;
  for(tmp = 0; tmp < nlri_len; tmp++)
  {
		printf("%u ", nlri_str[tmp]);
  }
  printf("\n");
  return nlri_len;
}

int
encode_flowspec_set (struct flowspec_index *index, u_int8_t *action_str, as_t as)
{
	struct flowspec_rule *rule, *next;
	//struct ecom_content *action;
	struct ecommunity_val *eval;
	int i,j = 0;
	int action_len = 0;
	for (rule = index->set_list.head; rule; rule = next)
	  {
		
		next = rule->next;
		//action_str[action_len++] = ECOMMUNITY_ENCODE_TRANS_EXP;
		//action_str[action_len++] = rule->cmd->type;
		//action = rule->value;
		eval = rule->value;
		if(rule->cmd->type == ECOMMUNITY_TRAFFIC_RATE)
		{
			eval->val[2] = as >> 8 & 0xff;
			eval->val[3] = as & 0xff;
		}
		for(i = 0; i < 8; i++)
			action_str[action_len++] = eval->val[i];
			
		printf("the %d rule: ", ++j);	
		for(i = 0; i < ECOMMUNITY_SIZE; i++)
			printf("%u ", action_str[action_len-ECOMMUNITY_SIZE+i]);
		printf("\n");
	  }
	return action_len;
}

DEFUN (show_flowspec_nlri,
       show_flowspec_nlri_cmd,
       "show flowspec nlri",
       "Show information"
       "Flowspec\n"
       "NLRI\n")
{
  return bgp_show_flowspec_nlri (vty, vty->index);
}

DEFUN (show_flowspec_port,
       show_flowspec_port_cmd,
       "show flowspec port",
       "Show information"
       "Flowspec\n"
       "Port number\n")
{
  return show_bgp_flowspec_match (vty, vty->index, "port");
}

DEFUN (match_flowspec_prefix,
       match_flowspec_prefix_cmd,
       "match (destination-address|source-address) A.B.C.D/M",
       "Flowspec Match\n"
       "Match based on destination address\n"
       "Match based on source address\n"
       "destination address\n")
{
  return bgp_flowspec_match_add (vty, vty->index, argv[0], argv[1]);
}

DEFUN (match_flowspec_protocol,
       match_flowspec_protocol_cmd,
       "match protocol <0-255>",
       MATCH_STR
       "Match based on protocol\n"
       "An IP Protocol Number\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "protocol", argv[0]);
}

DEFUN (match_flowspec_protocol_two_args,
       match_flowspec_protocol_two_args_cmd,
       "match protocol <0-255> <0-255>",
       MATCH_STR
       "Match based on protocol\n"
       "Minimum IP Protocol Number\n"
       "Maximum IP Protocol Number\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[0]);
	bgp_flowspec_match_add (vty, vty->index, "protocol", str1);
	strcat(str2, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, "protocol", str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_port,
       match_flowspec_port_cmd,
       "match port <0-65535>",
       MATCH_STR
       "Match based on port\n"
       "Port number\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "port", argv[0]);
}

DEFUN (match_flowspec_port_two_args,
       match_flowspec_port_two_args_cmd,
       "match port <0-65535> <0-65535>",
       MATCH_STR
       "Match based on port\n"
       "Minimum Port number\n"
       "Maximum Port number\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[0]);
	bgp_flowspec_match_add (vty, vty->index, "port", str1);
	strcat(str2, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, "port", str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_dest_src_port,
       match_flowspec_dest_src_port_cmd,
       "match (destination-port|source-port) <0-65535>",
       MATCH_STR
       "Match based on destination port\n"
       "Match based on source port\n"
       "Port number\n")
{
  return bgp_flowspec_match_add (vty, vty->index, argv[0], argv[1]);
}

DEFUN (match_flowspec_dest_src_port_two_args,
       match_flowspec_dest_src_port_two_args_cmd,
       "match (destination-port|source-port) <0-65535> <0-65535>",
       MATCH_STR
	   "Match based on destination port\n"
	   "Match based on source port\n"
       "Minimum Port number\n"
       "Maximum Port number\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, argv[0], str1);
	strcat(str2, argv[2]);
	bgp_flowspec_match_add (vty, vty->index, argv[0], str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_icmp_type,
       match_flowspec_icmp_type_cmd,
       "match icmp-type <0-255>",
       MATCH_STR
       "Match based on ICMP type\n"
       "Type number\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "icmp-type", argv[0]);
}

DEFUN (match_flowspec_icmp_type_two_args,
       match_flowspec_icmp_type_two_args_cmd,
       "match icmp-type <0-255> <0-255>",
       MATCH_STR
	   "Match based on ICMP type\n"
       "Minimum ICMP type\n"
       "Maximum ICMP type\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[0]);
	bgp_flowspec_match_add (vty, vty->index, "icmp-type", str1);
	strcat(str2, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, "icmp-type", str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_icmp_code,
       match_flowspec_icmp_code_cmd,
       "match icmp-code <0-255>",
       MATCH_STR
       "Match based on ICMP code\n"
       "Type number\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "icmp-code", argv[0]);
}

DEFUN (match_flowspec_icmp_code_two_args,
       match_flowspec_icmp_code_two_args_cmd,
       "match icmp-code <0-255> <0-255>",
       MATCH_STR
	   "Match based on ICMP code\n"
       "Minimum ICMP code\n"
       "Maximum ICMP code\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[0]);
	bgp_flowspec_match_add (vty, vty->index, "icmp-code", str1);
	strcat(str2, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, "icmp-code", str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_tcp_flag,
       match_flowspec_tcp_flag_cmd,
       "match tcp-flag <1-4095>",
       MATCH_STR
       "Match based on TCP flag\n"
       "TCP flag value (Enter Hex value)\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "tcp-flag", argv[0]);
}

DEFUN (match_flowspec_packet_length,
       match_flowspec_packet_length_cmd,
       "match packet length <0-65535>",
       MATCH_STR
       "Match based on packet length\n"
       "packet length\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "packet length", argv[0]);
}

DEFUN (match_flowspec_packet_length_two_args,
       match_flowspec_packet_length_two_args_cmd,
       "match packet length <0-65535> <0-65535>",
       MATCH_STR
	   "Match based on packet length\n"
       "Minimum packet length\n"
       "Maximum packet length\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[0]);
	bgp_flowspec_match_add (vty, vty->index, "packet length", str1);
	strcat(str2, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, "packet length", str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_dscp,
       match_flowspec_dscp_cmd,
       "match dscp <0-63>",
       MATCH_STR
       "Match based on DSCP\n"
       "DSCP Value\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "dscp", argv[0]);
}

DEFUN (match_flowspec_dscp_two_args,
       match_flowspec_dscp_two_args_cmd,
       "match dscp <0-63> <0-63>",
       MATCH_STR
	   "Match based on DSCP\n"
       "Minimum DSCP Value\n"
       "Maximum DSCP Value\n")
{
	char str1[10] = ">";
	char str2[10] = "<";

	strcat(str1, argv[0]);
	bgp_flowspec_match_add (vty, vty->index, "dscp", str1);
	strcat(str2, argv[1]);
	bgp_flowspec_match_add (vty, vty->index, "dscp", str2);
	return CMD_SUCCESS;
}

DEFUN (match_flowspec_fragment_type,
       match_flowspec_fragment_type_cmd,
       "match fragment-type (dont-fragment|first-fragment|is-fragment|last-fragment)",
       MATCH_STR
       "Match based on Fragment type for a packet\n"
       "Match don't-Fragment bit\n"
       "Match first fragment bit\n"
       "Match is-fragment bit\n"
       "Match last fragment bit\n")
{
  return bgp_flowspec_match_add (vty, vty->index, "fragment-type", argv[0]);
}

DEFUN (set_flowspec_traffic_rate,
       set_flowspec_traffic_rate_cmd,
       "set traffic-rate <1-4294967295>",
       "set\n"
       "Traffic rate\n"
       "Committed Information Rate\n")
{
  return bgp_flowspec_set_add (vty, vty->index, "traffic-rate", argv[0]);
}

DEFUN (set_flowspec_traffic_action,
       set_flowspec_traffic_action_cmd,
       "set traffic-action (terminal|sample|distribute)",
       "set\n"
       "Traffic action\n"
       "terminal\n"
       "sample\n")
{
  return bgp_flowspec_set_add (vty, vty->index, "traffic-action", argv[0]);
}

DEFUN (set_flowspec_ecommunity_rt,
       set_flowspec_ecommunity_rt_cmd,
       "set extcommunity rt .ASN:nn_or_IP-address:nn",
       SET_STR
       "Traffic redirect VRF\n"
       "Route Target extended community\n"
       "VPN extended community\n")
{
  int ret;
  char *str;

  str = argv_concat (argv, argc, 0);
  ret = bgp_flowspec_set_add (vty, vty->index, "extcommunity rt", str);
  XFREE (MTYPE_TMP, str);

  return ret;
}

DEFUN (set_flowspec_dscp,
       set_flowspec_dscp_cmd,
       "set dscp <0-63>",
       "set\n"
       "Traffic marking\n"
       "DSCP\n")
{
  return bgp_flowspec_set_add (vty, vty->index, "dscp", argv[0]);
}

DEFUN (set_flowspec_redirect_next_hop,
       set_flowspec_redirect_next_hop_cmd,
       "redirect next-hop A.B.C.D/M",
       "redirect IP NH\n"
       "next hop\n"
       "next hop address\n")
{
  return bgp_flowspec_set_add (vty, vty->index, "next-hop", argv[0]);
}

/* Free route map's compiled `ip address' value. */
static void
flowspec_match_free (void *rule)
{
  XFREE (MTYPE_FLOWSPEC_COMPILED, rule);
}

static void
flowspec_set_free (void *rule)
{
  XFREE (MTYPE_FLOWSPEC_COMPILED, rule);
}

static void *
fs_match_prefix_compile (const char * arg)
{
	int ret;
	struct prefix *p;
	printf("arg=%s\n",arg);
	
	p = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct prefix));
	/* Convert IP prefix string to struct prefix. */
  	ret = str2prefix (arg, p);
	if (! ret)
    {
      printf ("Malformed prefix\n");
      //return CMD_WARNING;
    }
	apply_mask (p);
	printf("fs_match_prefix_compile(family = %u, p_len=%u, prefix=%u)\n", p->family, p->prefixlen, p->u.prefix4.s_addr);
	return p;
}

/* IEEE.754.1985 floating point format convert*/
union traffic_rate
{
	float rate_float;
	u_int8_t rate_byte[4];
};

static void *
fs_set_traffic_rate_compile(const char * arg)
{
	//struct ecom_content *rate;
	struct ecommunity_val *eval;
	union traffic_rate data;
	
	eval = XCALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecommunity_val));
	if (! eval)
	  return NULL;
	
	//rate = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecom_content));
	data.rate_float = atoi(arg);
	
	eval->val[0] = ECOMMUNITY_ENCODE_TRANS_EXP;
	eval->val[1] = ECOMMUNITY_TRAFFIC_RATE;	
	
	/* 2-byte AS*/
	eval->val[2] = 0;
	eval->val[3] = 0;

	/* 4-byte float*/
	eval->val[4] = data.rate_byte[3];
	eval->val[5] = data.rate_byte[2];
	eval->val[6] = data.rate_byte[1];
	eval->val[7] = data.rate_byte[0];


	return eval;
}

static void *
fs_set_traffic_action_compile(const char * arg)
{
	//struct ecom_content *value;

	//value = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecom_content));

	struct ecommunity_val *eval;
	
	eval = XCALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecommunity_val));
	if (! eval)
	  return NULL;

	eval->val[0] = ECOMMUNITY_ENCODE_TRANS_EXP;
	eval->val[1] = ECOMMUNITY_TRAFFIC_ACTION;	

	eval->val[2] = 0;
	eval->val[3] = 0;
	eval->val[4] = 0;
	eval->val[5] = 0;
	eval->val[6] = 0;
	eval->val[7] = 0;

	if(!strcmp(arg, "terminal"))
		eval->val[5] = 1 << FLOWSPEC_TRAFFIC_ACTION_TERMINAL;
	if(!strcmp(arg, "sample"))
		eval->val[5] = 1 << FLOWSPEC_TRAFFIC_ACTION_SAMPLE;
	if(!strcmp(arg, "distribute"))
		eval->val[5] = 1 << FLOWSPEC_TRAFFIC_ACTION_DISTRIBUTE;

	return eval;
}

static void *
fs_set_dscp_compile(const char * arg)
{
	//struct ecom_content *dscp;

	//dscp = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecom_content));
	struct ecommunity_val *eval;
	
	eval = XCALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecommunity_val));
	if (! eval)
	  return NULL;

	eval->val[0] = ECOMMUNITY_ENCODE_TRANS_EXP;
	eval->val[1] = ECOMMUNITY_TRAFFIC_MARKING;

	eval->val[2] = 0;
	eval->val[3] = 0;
	eval->val[4] = 0;
	eval->val[5] = 0;
	eval->val[6] = 0;
	eval->val[7] = atoi(arg);
	//dscp_val[6] = 0;
	//dscp_val[7] = 0;

	return eval;
}

struct flowspec_rule_cmd fs_match_dest_prefix_cmd =
{
  "destination-address",
  NULL,
  fs_match_prefix_compile,
  flowspec_match_free,
  FLOWSPEC_DEST_PREFIX
};

struct flowspec_rule_cmd fs_match_src_prefix_cmd =
{
  "source-address",
  NULL,
  fs_match_prefix_compile,
  flowspec_match_free,
  FLOWSPEC_SRC_PREFIX
};

static void *
fs_match_port_compile (const char * arg)
{
	struct fs_map_value *fs_port;

	fs_port = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct fs_map_value));
	if(isdigit(*arg))
	{
		fs_port->value = atoi(arg);
		fs_port->operator = FLOWSPEC_OPERATOR_EQUALL;
		// printf("fs_match_port_compile(arg=%s, value=%d, operator=%d)\n",arg, fs_port->value, fs_port->operator);
	}
	else
	{
		fs_port->value = atoi(arg+1);
		if(*arg == '>')
			fs_port->operator = FLOWSPEC_OPERATOR_GE;
		else
			fs_port->operator = FLOWSPEC_OPERATOR_LE;
	}
	return fs_port;
}

/* only contain value */
static void *
fs_match_tcp_flag_compile (const char * arg)
{
	/* 1- or 2-byte bitmask*/
	struct fs_map_value *val;

	val = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct fs_map_value));
	val->value = atoi(arg);
	val->operator = 0;
	
	return val;
}

static void *
fs_match_fragment_type_compile (const char * arg)
{
	struct fs_map_value *val;

	val = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct fs_map_value));
	if(!strcmp(arg, "dont-fragment"))
		val->value = 1 << 0;
	if(!strcmp(arg, "first-fragment"))
		val->value = 1 << 1;
	if(!strcmp(arg, "is-fragment"))
		val->value = 1 << 2;
	if(!strcmp(arg, "last-fragment"))
		val->value = 1 << 3;

	val->operator = 0;
	return val;
}

#if 0
static void *
fs_match_icmp_type_compile (const char * arg)
{
	u_int8_t *value;

	value = XMALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct u_int8_t));
	value = atoi(arg);
	return value;
}
#endif

struct flowspec_rule_cmd fs_match_protocol_cmd =
{
  "protocol",
  NULL,
  fs_match_port_compile,
  flowspec_match_free,
  FLOWSPEC_IP_PROTOCOL
};

/* Route map commands for ip address matching. */
struct flowspec_rule_cmd fs_match_port_cmd =
{
  "port",
  NULL,
  fs_match_port_compile,
  flowspec_match_free,
  FLOWSPEC_PORT
};

/**/
struct flowspec_rule_cmd fs_match_dest_port_cmd =
{
  "destination-port",
  NULL,
  fs_match_port_compile,
  NULL,
  FLOWSPEC_DEST_PORT
};

struct flowspec_rule_cmd fs_match_src_port_cmd =
{
  "source-port",
  NULL,
  fs_match_port_compile,
  NULL,
  FLOWSPEC_SRC_PORT
};

struct flowspec_rule_cmd fs_match_icmp_type_cmd =
{
  "icmp-type",
  NULL,
  fs_match_port_compile,
  NULL,
  FLOWSPEC_ICMP_TYPE
};

struct flowspec_rule_cmd fs_match_icmp_code_cmd =
{
  "icmp-code",
  NULL,
  fs_match_port_compile,
  NULL,
  FLOWSPEC_ICMP_CODE
};

struct flowspec_rule_cmd fs_match_tcp_flag_cmd =
{
  "tcp-flag",
  NULL,
  fs_match_tcp_flag_compile,
  NULL,
  FLOWSPEC_TCP_FLAGS
};

struct flowspec_rule_cmd fs_match_packet_length_cmd =
{
  "packet length",
  NULL,
  fs_match_port_compile,
  NULL,
  FLOWSPEC_PKT_LEN
};

struct flowspec_rule_cmd fs_match_dscp_cmd =
{
  "dscp",
  NULL,
  fs_match_port_compile,
  NULL,
  FLOWSPEC_DSCP
};

struct flowspec_rule_cmd fs_match_fragment_type_cmd =
{
  "fragment-type",
  NULL,
  fs_match_fragment_type_compile,
  NULL,
  FLOWSPEC_FRAGMENT
};

struct flowspec_rule_cmd fs_set_traffic_rate_cmd =
{
  "traffic-rate",
  NULL,
  fs_set_traffic_rate_compile,
  flowspec_set_free,
  ECOMMUNITY_TRAFFIC_RATE
};

struct flowspec_rule_cmd fs_set_traffic_action_cmd =
{
  "traffic-action",
  NULL,
  fs_set_traffic_action_compile,
  flowspec_set_free,
  ECOMMUNITY_TRAFFIC_ACTION
};

/* Extended Communities token enum. */
enum ecommunity_token
{
  ecommunity_token_unknown = 0,
  ecommunity_token_rt,
  ecommunity_token_soo,
  ecommunity_token_val,
};


/* Compile function for set community. */
static void *
fs_set_ecommunity_rt_compile (const char *arg)
{
  struct ecommunity_val *eval;
  enum ecommunity_token token = ecommunity_token_unknown;

  eval = XCALLOC(MTYPE_FLOWSPEC_COMPILED, sizeof(struct ecommunity_val));
  if (! eval)
    return NULL;
  
  ecommunity_gettoken (arg, eval, &token);
  if (token == ecommunity_token_unknown)
  	return NULL;
  
  eval->val[0] = ECOMMUNITY_ENCODE_TRANS_EXP;
  eval->val[1] = ECOMMUNITY_REDIRECT_VRF;
  
  return eval;
}

/* Set community rule structure. */
struct flowspec_rule_cmd fs_set_ecommunity_rt_cmd = 
{
  "extcommunity rt",
  NULL,
  fs_set_ecommunity_rt_compile,
  flowspec_set_free,
  ECOMMUNITY_REDIRECT_VRF
};

#if 0
struct flowspec_rule_cmd fs_set_traffic_redirect_cmd =
{
  "traffic-redirect",
  NULL,
  fs_set_traffic_redirect_compile,
  flowspec_set_free,
  ECOMMUNITY_ROUTE_TARGET
};
#endif
struct flowspec_rule_cmd fs_set_dscp_cmd =
{
  "dscp",
  NULL,
  fs_set_dscp_compile,
  flowspec_set_free,
  ECOMMUNITY_TRAFFIC_MARKING
};
#if 0
struct flowspec_rule_cmd fs_set_next_hop_cmd =
{
  "next-hop",
  NULL,
  fs_set_next_hop_compile,
  flowspec_set_free,
  ECOMMUNITY_REDIRECT_IP_NH
};
#endif
void
bgp_flowspec_init (void)
{
	/* Install route map top node. */
	install_node (&fs_node, NULL);
	
	/* Install route map commands. */
	install_default (FLOWSPEC_NODE);
	install_element (CONFIG_NODE, &flowspec_cmd);

	flowspec_init ();
	//flowspec_init_vty ();
	//flowspec_add_hook (bgp_flowspec_update);
	//flowspec_delete_hook (bgp_flowspec_update);
	flowspec_install_match (&fs_match_dest_prefix_cmd);
	flowspec_install_match (&fs_match_src_prefix_cmd);
	flowspec_install_match (&fs_match_protocol_cmd);
	flowspec_install_match (&fs_match_port_cmd);
	flowspec_install_match (&fs_match_dest_port_cmd);
	flowspec_install_match (&fs_match_src_port_cmd);
	flowspec_install_match (&fs_match_icmp_type_cmd);
	flowspec_install_match (&fs_match_icmp_code_cmd);
	flowspec_install_match (&fs_match_tcp_flag_cmd);	
	flowspec_install_match (&fs_match_packet_length_cmd);
	flowspec_install_match (&fs_match_dscp_cmd);
	flowspec_install_match (&fs_match_fragment_type_cmd);
	
	flowspec_install_set (&fs_set_traffic_rate_cmd);
	flowspec_install_set (&fs_set_traffic_action_cmd);
	flowspec_install_set (&fs_set_ecommunity_rt_cmd);
	flowspec_install_set (&fs_set_dscp_cmd);
	//flowspec_install_set (&route_set_metric_cmd);

  /* BGP FS commands.*/
	install_element (FLOWSPEC_NODE, &match_flowspec_protocol_two_args_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_port_two_args_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_dest_src_port_two_args_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_icmp_type_two_args_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_icmp_code_two_args_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_packet_length_two_args_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_dscp_two_args_cmd);
	
	install_element (FLOWSPEC_NODE, &match_flowspec_prefix_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_protocol_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_port_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_dest_src_port_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_icmp_type_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_icmp_code_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_tcp_flag_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_packet_length_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_dscp_cmd);
	install_element (FLOWSPEC_NODE, &match_flowspec_fragment_type_cmd);

	install_element (FLOWSPEC_NODE, &set_flowspec_traffic_rate_cmd);
	install_element (FLOWSPEC_NODE, &set_flowspec_traffic_action_cmd);
	install_element (FLOWSPEC_NODE, &set_flowspec_ecommunity_rt_cmd);
	install_element (FLOWSPEC_NODE, &set_flowspec_dscp_cmd);
		
	install_element (FLOWSPEC_NODE, &show_flowspec_port_cmd);
	install_element (FLOWSPEC_NODE, &show_flowspec_nlri_cmd);
	//install_element (BGP_FLOWSPEC_NODE, &match_flowspec_port_two_args);
}
