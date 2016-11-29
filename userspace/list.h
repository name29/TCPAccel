//From https://github.com/paulchakravarti/list/blob/master/list.h

#include <stdlib.h>

typedef struct listNode {
    void *item;
    struct listNode *prev;
    struct listNode *next;
} listNode;

typedef struct list {
    struct listNode *head;
    struct listNode *tail;
} list;

list *list_init();
void list_free(list *l,void (*freeItem)(void *d));
void list_append(list *l, void *i);
void list_prepend(list *l, void *i);
int list_count(list *l);
listNode *list_nth(list *l, int n);
void list_insert(list *l, listNode *after, void *item);
void list_remove(list *l, listNode *remove, void (*freeItem)(void *d));
listNode *list_find(list *l, void *target, int (*cmp)(void *a,void *b));
void list_apply(list *l, void (*f)(void *d));
list *list_filter(list *l, int (*f)(void *d));
list *list_map(list *l, void *(*f)(void *d));
list *list_slice(list *l, int start, int end, void *(*dup) (void *i));
list *list_concat(list *l1, list *l2, void *(*dup) (void *i));
void list_debug(list *l, void(*pf) (void *i));
void list_sort(list *l, int(*cmp) (const void *i, const void *j));
