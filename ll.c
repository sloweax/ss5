#include "ll.h"
#include <stdlib.h>
#include <string.h>

LLNode *ll_node_create() {
	LLNode *ll = malloc(sizeof(LLNode));
	if (ll == NULL) return NULL;
	bzero(ll, sizeof(LLNode));
	return ll;
}

LL *ll_create() {
	LL *ll = malloc(sizeof(LL));
	if (ll == NULL) return NULL;
	ll->head = ll->tail = NULL;
	return ll;
}

void ll_node_free(LLNode *ll) {
	free(ll);
}

void ll_free(LL *ll) {
	LLNode *tmp = ll->head, *next;
	while (tmp) {
		next = tmp->next;
		ll_node_free(tmp);
		tmp = next;
	}
	free(ll);
}

void ll_append_node(LL *ll, LLNode *node) {
	if (ll->tail == NULL) {
		ll->tail = ll->head = node;
		return;
	}
	ll->tail->next = node;
	ll->tail = node;
}

int ll_append(LL *ll, void *data) {
	LLNode *node = ll_node_create();
	if (node == NULL) return 1;
	node->data = data;
	ll_append_node(ll, node);
	return 0;
}
