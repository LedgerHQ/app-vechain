/*******************************************************************************
 *   Ledger VeChain App
 *   (c) 2025 VeChain Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 ********************************************************************************/

#pragma once

#include <stddef.h>
#include <stdbool.h>

/**
 * Lightweight forward (singly-linked) and doubly-linked list helpers, modelled
 * after the same-named module in LedgerHQ/app-ethereum. Each list node embeds
 * its link field as the first member of the user struct so we can cast back
 * and forth.
 */

typedef struct flist_node_s {
    struct flist_node_s *next;
} flist_node_t;

typedef struct list_node_s {
    struct list_node_s *next;
    struct list_node_s *prev;
} list_node_t;

typedef void (*f_list_node_del)(void *);
typedef bool (*f_list_node_cmp)(const void *a, const void *b);

static inline void flist_push_back(flist_node_t **head, flist_node_t *node) {
    node->next = NULL;
    if (*head == NULL) {
        *head = node;
        return;
    }
    flist_node_t *tail = *head;
    while (tail->next != NULL) {
        tail = tail->next;
    }
    tail->next = node;
}

static inline void list_push_back(list_node_t **head, list_node_t *node) {
    node->next = NULL;
    if (*head == NULL) {
        node->prev = NULL;
        *head = node;
        return;
    }
    list_node_t *tail = *head;
    while (tail->next != NULL) {
        tail = tail->next;
    }
    tail->next = node;
    node->prev = tail;
}

static inline void list_pop_back(list_node_t **head, f_list_node_del del) {
    if (*head == NULL) {
        return;
    }
    list_node_t *tail = *head;
    while (tail->next != NULL) {
        tail = tail->next;
    }
    if (tail->prev != NULL) {
        tail->prev->next = NULL;
    } else {
        *head = NULL;
    }
    if (del != NULL) {
        del(tail);
    }
}

static inline void flist_clear(flist_node_t **head, f_list_node_del del) {
    flist_node_t *cur = *head;
    while (cur != NULL) {
        flist_node_t *next = cur->next;
        if (del != NULL) {
            del(cur);
        }
        cur = next;
    }
    *head = NULL;
}

static inline void list_clear(list_node_t **head, f_list_node_del del) {
    list_node_t *cur = *head;
    while (cur != NULL) {
        list_node_t *next = cur->next;
        if (del != NULL) {
            del(cur);
        }
        cur = next;
    }
    *head = NULL;
}

/**
 * Sort a forward list in-place using the provided comparator. The comparator
 * must return true when `a` should appear before `b`. The implementation is
 * a simple insertion sort so it does not allocate, but it does mutate the
 * `next` pointers of the nodes.
 */
static inline void flist_sort(flist_node_t **head, f_list_node_cmp cmp) {
    if (head == NULL || *head == NULL || (*head)->next == NULL) return;
    flist_node_t *sorted = NULL;
    flist_node_t *cur = *head;
    while (cur != NULL) {
        flist_node_t *next = cur->next;
        if (sorted == NULL || cmp(cur, sorted)) {
            cur->next = sorted;
            sorted = cur;
        } else {
            flist_node_t *iter = sorted;
            while (iter->next != NULL && !cmp(cur, iter->next)) {
                iter = iter->next;
            }
            cur->next = iter->next;
            iter->next = cur;
        }
        cur = next;
    }
    *head = sorted;
}
