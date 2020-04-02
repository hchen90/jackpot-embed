/* $ @  list.h  
 * Copyright (C) 2020 Hsiang Chen 
 * 
 * This software is free software, you may redistribute it under the terms of GNU General Public License v3. 
 * For detail see <http://www.gnu.org/licenses>
 * 
 * This file is generated from Makefile, DO NOT EDIT it.
 * */
#ifndef  _LIST_H_
#define  _LIST_H_
/* start of  list.h.in  */
#define SUB_DATA 0x0001
#define SUB_LIST 0x0002
#define SUB_PTR  0x0004
#define SUB_LEN  0x0008
#define SUB_DC   0x0010
#define SUB_DS   0x0020
#define SUB_DI   0x0080
#define SUB_DL   0x0100
#define SUB_FREE 0x0200

struct _ListNode;

typedef struct _List {
  struct _ListNode* head;
  struct _ListNode* tail;
  size_t length;
  void (* free)(struct _List*);
} List;

typedef struct _ListNode {
  union {
    struct {
      void* ptr;
      size_t len;
      char dc;
      short ds;
      int di;
      long dl;
    } data;
    struct _List list;
  };
  struct {
    int sub;
  } tags;
  struct _ListNode* next;
  struct _ListNode* previous;
} ListNode;
/* end of  list.h.in  */
int list_init(List* lo);
void list_uinit(List* lo);
ListNode* list_get(List* lo, size_t ix);
int list_insert(List* lo, size_t ix, ListNode* no); /* 0- insert before header, -1 to append after tailer */
int list_remove(List* lo, size_t ix);
size_t list_length(List* lo);
#endif  // _LIST_H_
