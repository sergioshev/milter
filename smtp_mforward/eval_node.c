#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include "eval_node.h"

int eval(void *p1, void *p 
{
  if ( p1 == NULL || p2 == NULL ) {
    return 0;
  }
  //printf("comparing %s against %s result %d\n",p1,p2,strcmp(p1,p2));
  if ( strcmp ( (char *) p1, (char *) p2 ) != 0 ) {
    return 0;
  }
  return 1;
}

