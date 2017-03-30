#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "str_utils.h"


char *strrev(char **string)
{
  int l = strlen(*string);
  if (l<1) {
    return *string;
  }
  int start=0, end=--l;
  while (start < end)
  {
    char aux = (*string)[start];
    (*string)[start] = (*string)[end];
    (*string)[end] = aux;
    start++;
    end--;
  }
  return *string;
}

char *parse_domain(char *address)
{
  char *p = strrchr(address,'@');
  char *p2;

  if ( p == NULL ) {
    return NULL;
  }
  //printf("adress %s arroba %s\n",address,p);
  int l = strlen( p );
  if ( l <= 3 ) {
    return NULL;
  }
  if ( ( p2 = strrchr( p, '.' ) ) == NULL ) {
    return NULL;
  }
  if ( strlen( p2 ) <= 1 ) {
    return NULL;
  }
  
  p++;
  char *ret = (char *)malloc( l );
  strncpy( ret, p, l - 1 );
  //printf("ret p l - 1  %s\n",ret);
  *(ret + l) = '\0';
  //printf("ret %s\n",ret);
  return ret;
}
