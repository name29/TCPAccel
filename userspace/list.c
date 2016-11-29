//From  https://github.com/paulchakravarti/list/blob/master/list.c

#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "list.h"

list *list_init() {
    list *l = malloc(sizeof(list));
    assert(l);
    l->head = NULL;
    l->tail = NULL;
    return l;
}

void list_free(list *l,void (*freeItem)(void *d)) {
    listNode *i = l->head;
    listNode *n;
    while (i != NULL) {
        if (freeItem != NULL) {
            freeItem(i->item);
        }
        n = i->next;
        free(i);
        i = n;
    }
    free(l);
}

void list_append(list *l, void *i) {
    listNode *n = (listNode *) malloc(sizeof(listNode));
    assert(n);
    listNode *t = l->tail;
    n->item = i;
    if (t == NULL) {
        n->prev = NULL;
        n->next = NULL;
        l->head = n;
        l->tail = n;
    } else {
        n->prev = t;
        n->next = NULL;
        t->next = n;
        l->tail = n;
    }
}

void list_prepend(list *l, void *i) {
    listNode *n = (listNode *) malloc(sizeof(listNode));
    assert(n);
    listNode *h = l->head;
    n->item = i;
    if (h == NULL) {
        n->prev = NULL;
        n->next = NULL;
        l->head = n;
        l->tail = n;
    } else {
        n->prev = NULL;
        n->next = h;
        h->prev = n;
        l->head = n;
    }
}

int list_count(list *l) {
    int n = 0;
    listNode *i = l->head;
    while (i != NULL) {
        ++n;
        i = i->next;
    }
    return n;
}

listNode *list_nth(list *l, int n) {
    listNode *i = l->head;
    int c = 0;
    if (n < 0) {
        n = list_count(l) + n;
    }
    while (i != NULL) {
        if (c == n) {
            return i;
        } 
        ++c;
        i = i->next;
    }
    return NULL;
}

void list_insert(list *l, listNode *after, void *item) {
    listNode *n = l->head;
    while (n != NULL) {
        if (n == after) {
            listNode *new = (listNode *) malloc(sizeof(listNode));
            assert(new);
            new->item = item;
            new->prev = n;
            if (n->next) {
                new->next = n->next;
                n->next->prev = new;
            } else {
                new->next = NULL;
            }
            n->next = new;
            if (after == l->tail) {
                l->tail = new;
            }
            break;
        }
        n = n->next;
    }
}

void list_remove(list *l, listNode *remove, void (*freeItem)(void *d)) {
    listNode *n = l->head;
    while (n != NULL) {
        if (n == remove) {
            if (n->prev) {
                n->prev->next = n->next;
            }
            if (n->next) {
                n->next->prev = n->prev;
            }
            if (n == l->head) {
                l->head = n->next;
            }
            if (n == l->tail) {
                l->tail = n->prev;
            }
            if (freeItem != NULL) {
                freeItem(n->item);
            }
            free(n);
            break;
        }
        n = n->next;
    }
}

listNode *list_find(list *l, void *target, int (*cmp)(void *a,void *b)) {
    listNode *n = l->head;
    while (n != NULL) {
        if (cmp(n->item,target) == 0) {
            return n;
        }
        n = n->next;
    }
    return NULL;
}

void list_apply(list *l, void (*f)(void *d)) {
    listNode *n = l->head;
    while (n != NULL) {
        f(n->item);
        n = n->next;
    }
}

list *list_filter(list *l, int (*f)(void *d)) {
    list *r = list_init();
    listNode *n = l->head;
    while (n != NULL) {
        if (f(n->item)) {
            list_append(r,n->item);
        }
        n = n->next;
    }
    return r;
}

list *list_map(list *l, void *(*f)(void *d)) {
    list *r = list_init();
    listNode *n = l->head;
    while (n != NULL) {
        list_append(r,f(n->item));
        n = n->next;
    }
    return r;
}

list *list_slice(list *l, int start, int end, void *(*dup) (void *i)) {
    list *r = list_init();
    listNode *i = l->head;
    int c = 0;
    if (start < 0) {
        start = list_count(l) + start;
    }
    if (end < 0) {
        end = list_count(l) + end;
    }
    while (i != NULL) {
        if (c >= start && c <= end) {
            if (dup) {
                list_append(r,dup(i->item));
            } else {
                list_append(r,i->item);
            }
        }
        ++c;
        i = i->next;
    }
    return r;
}


list *list_concat(list *l1, list *l2, void *(*dup) (void *i)) {
    list *r = list_init();
    listNode *i = l1->head;
    while (i != NULL) {
        if (dup) {
            list_append(r,dup(i->item));
        } else {
            list_append(r,i->item);
        }
        i = i->next;
    }
    i = l2->head;
    while (i != NULL) {
        if (dup) {
            list_append(r,dup(i->item));
        } else {
            list_append(r,i->item);
        }
        i = i->next;
    }
    return r;
}

void list_debug(list *l, void(*pf) (void *i)) {
    printf("--- List [%p]: head -> %p / tail -> %p\n",l,l->head,l->tail);
    listNode *n = l->head;
    while (n != NULL) {
        printf("  + Item [%p]: data -> %p / prev -> %p / next -> %p\n",
                n,n->item,n->prev,n->next);
        if (pf != NULL) {
            pf(n->item);
        }
        n = n->next;
    }
}

void list_sort(list *l, int(*cmp) (const void *i, const void *j)) {
    /* Copy list into array */
    int nmemb = list_count(l);
    void **base = malloc(nmemb * sizeof(void *)); 
    bzero(base,nmemb * sizeof(void *));
    void **p = base;
    assert(base);
    listNode *n = l->head;
    while (n != NULL) {
        *p = n->item;
        ++p;
        n = n->next;
    }
    /* qsort array */
    qsort(base,nmemb,sizeof(void*),cmp);
    n = l->head;
    p = base;
    while (n != NULL) {
        n->item = *p;
        ++p;
        n = n->next;
    }
    free(base);
}
