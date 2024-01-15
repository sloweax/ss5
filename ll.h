#pragma once

struct LLNode {
	struct LLNode *next;
	void *data;
};

struct LL {
	struct LLNode *head;
	struct LLNode *tail;
};

typedef struct LLNode LLNode;
typedef struct LL LL;

LL *ll_create();
int ll_append(LL *ll, void *data);
void ll_free(LL *ll);

LLNode *ll_node_create();
void ll_node_free(LLNode *ll);
