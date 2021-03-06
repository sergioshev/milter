#ifndef LINKED_LIST_H
#define LINKED_LIST_H 1
typedef struct list_node {
  void * data;
  //size_t len h;
  struct list_node *next_node;
} linked_list;


linked_list *allocate_node();
linked_list *init_list();
linked_list *add_data(void *data, linked_list **head);
void destroy_linked_list(linked_list *head);
int in_list (linked_list *head, void *needle, int (*eval)(void *p1, void *p2));
#endif

