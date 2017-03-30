#include <stdlib.h>
#include <stdio.h>
#include "linked_list.h"

linked_list *allocate_node()
{
  linked_list *new_node = (linked_list*)malloc(sizeof(linked_list));
  if (new_node == NULL) {
    fprintf(stderr,"Error: Trying allocate memory for linked_list node");
    return NULL;
  }
  new_node->next_node = NULL;
  return new_node;
}


linked_list *init_list()
{
  return allocate_node();
}


linked_list *add_data(void *data, linked_list **head)
{
  linked_list *new_node = allocate_node();
  new_node->data = data;
  new_node->next_node = *head;
  *head = new_node;
  return *head;
}

void destroy_linked_list(linked_list *head)
{
  if ( head != NULL) {
    destroy_linked_list(head->next_node);
    free(head->data);
    if (head->next_node != NULL) {
      free(head);
    }
  }
}

int in_list (linked_list *head, void *needle, int (*eval)(void *, void *))
{
  if ( head == NULL) {
    return 0;
  }
  if  ( ! (*eval)(needle, head->data) ) {
    return in_list(head->next_node, needle, eval);
  } else {
    return 1;
  }
}

