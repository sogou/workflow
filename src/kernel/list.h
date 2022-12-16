#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

/*
 * Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct list_head *node,
							  struct list_head *prev,
							  struct list_head *next)
{
	next->prev = node;
	node->next = next;
	node->prev = prev;
	prev->next = node;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void list_add(struct list_head *node, struct list_head *head)
{
	__list_add(node, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void list_add_tail(struct list_head *node,
								 struct list_head *head)
{
	__list_add(node, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void list_move_tail(struct list_head *list,
								  struct list_head *head)
{
	__list_del(list->prev, list->next);
	list_add_tail(list, head);
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void __list_splice(struct list_head *list,
								 struct list_head *head)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	struct list_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(struct list_head *list, struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head);
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct list_head *list,
									struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head);
		INIT_LIST_HEAD(list);
	}
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe	-	iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop counter.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		 pos = n, n = pos->next)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, typeof (*pos), member); \
		 &pos->member != (head); \
		 pos = list_entry(pos->member.next, typeof (*pos), member))

/**
 * Single-linked list. Added by Xie Han <xiehan@sogou-inc.com>.
 */

struct slist_node {
	struct slist_node *next;
};

struct slist_head {
	struct slist_node first, *last;
};

#define SLIST_HEAD_INIT(name)	{ { (struct slist_node *)0 }, &(name).first }

#define SLIST_HEAD(name) \
	struct slist_head name = SLIST_HEAD_INIT(name)

static inline void INIT_SLIST_HEAD(struct slist_head *list)
{
	list->first.next = (struct slist_node *)0;
	list->last = &list->first;
}

static inline void slist_add_after(struct slist_node *node,
								   struct slist_node *prev,
								   struct slist_head *list)
{
	node->next = prev->next;
	prev->next = node;
	if (!node->next)
		list->last = node;
}

static inline void slist_add_head(struct slist_node *node,
								  struct slist_head *list)
{
	slist_add_after(node, &list->first, list);
}

static inline void slist_add_tail(struct slist_node *node,
								  struct slist_head *list)
{
	node->next = (struct slist_node *)0;
	list->last->next = node;
	list->last = node;
}

static inline void slist_del_after(struct slist_node *prev,
								   struct slist_head *list)
{
	prev->next = prev->next->next;
	if (!prev->next)
		list->last = prev;
}

static inline void slist_del_head(struct slist_head *list)
{
	slist_del_after(&list->first, list);
}

static inline int slist_empty(struct slist_head *list)
{
	return !list->first.next;
}

static inline void __slist_splice(struct slist_head *list,
								  struct slist_node *at,
								  struct slist_head *head)
{
	list->last->next = at->next;
	at->next = list->first.next;
	if (!list->last->next)
		head->last = list->last;
}

static inline void slist_splice(struct slist_head *list,
								struct slist_node *at,
								struct slist_head *head)
{
	if (!slist_empty(list))
		__slist_splice(list, at, head);
}

static inline void slist_splice_init(struct slist_head *list,
									 struct slist_node *at,
									 struct slist_head *head)
{
	if (!slist_empty(list)) {
		__slist_splice(list, at, head);
		INIT_SLIST_HEAD(list);
	}
}

#define slist_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

#define slist_for_each(pos, head) \
	for (pos = (head)->first.next; pos; pos = pos->next)

#define slist_for_each_safe(pos, prev, head) \
	for (prev = &(head)->first, pos = prev->next; pos; \
		 prev = prev->next == pos ? pos : prev, pos = prev->next)

#define slist_for_each_entry(pos, head, member) \
	for (pos = slist_entry((head)->first.next, typeof (*pos), member); \
		 &pos->member != (struct slist_node *)0; \
		 pos = slist_entry(pos->member.next, typeof (*pos), member))

#endif
