#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <assert.h>

#include "sbrk.h"

/* RED-BLACK TREE IMPLEMENTATION */

typedef enum {
    RED, BLACK
} color_t;

typedef struct node {
    struct node *left;
    struct node *right;
    struct node *p;

    // USED FOR MERGING
    struct node *prev;
    struct node *next;

    color_t color;
    size_t size;
    bool used;
} node_t;

typedef struct {
    node_t *root;
    node_t *NIL;
    node_t *last_alloc;
} rbt_t;

void left_rotate(rbt_t *tree, node_t *x) {
    node_t *y = x->right;
    x->right = y->left;
    if (y->left != tree->NIL)
        y->left->p = x;
    y->p = x->p;
    if (x->p == tree->NIL)
        tree->root = y;
    else if (x == x->p->left)
        x->p->left = y;
    else
        x->p->right = y;
    y->left = x;
    x->p = y;
}

void right_rotate(rbt_t *tree, node_t *x) {
    node_t *y = x->left;
    x->left = y->right;
    if (y->right != tree->NIL)
        y->right->p = x;
    y->p = x->p;
    if (x->p == tree->NIL)
        tree->root = y;
    else if (x == x->p->left)
        x->p->left = y;
    else
        x->p->right = y;
    y->right = x;
    x->p = y;
}

void insert_meta_fixup(rbt_t *tree, node_t *z) {
    while (z->p->color == RED) {
        if (z->p == z->p->p->left) {
            node_t *y = z->p->p->right;
            if (y->color == RED) {
                z->p->color = BLACK;
                y->color = BLACK;
                z->p->p->color = RED;
                z = z->p->p;
            } else {
                if (z == z->p->right) {
                    z = z->p;
                    left_rotate(tree, z);
                }
                z->p->color = BLACK;
                z->p->p->color = RED;
                right_rotate(tree, z->p->p);
            }
        } else {
            node_t *y = z->p->p->left;
            if (y->color == RED) {
                z->p->color = BLACK;
                y->color = BLACK;
                z->p->p->color = RED;
                z = z->p->p;
            } else {
                if (z == z->p->left) {
                    z = z->p;
                    right_rotate(tree, z);
                }
                z->p->color = BLACK;
                z->p->p->color = RED;
                left_rotate(tree, z->p->p);
            }
        }
    }
    tree->root->color = BLACK;
}

node_t *insert_meta(rbt_t *tree, node_t *z) {
    node_t *y = tree->NIL;
    node_t *cur = tree->root;
    while (cur != tree->NIL) {
        y = cur;
        if (z->size < cur->size)
            cur = cur->left;
        else
            cur = cur->right;
    }
    z->p = y;
    if (y == tree->NIL)
        tree->root = z;
    else if (z->size < y->size)
        y->left = z;
    else
        y->right = z;
    z->left = tree->NIL;
    z->right = tree->NIL;
    z->color = RED;
    insert_meta_fixup(tree, z);
    return z;
}

void transplant(rbt_t *tree, node_t *u, node_t *v) {
    if (u->p == tree->NIL)
        tree->root = v;
    else if (u == u->p->left)
        u->p->left = v;
    else
        u->p->right = v;
    v->p = u->p;
}

void remove_meta_fixup(rbt_t *tree, node_t *x) {
    while (x != tree->root && x->color == BLACK) {
        if (x == x->p->left) {
            node_t *w = x->p->right;
            if (w->color == RED) {
                w->color = BLACK;
                x->p->color = RED;
                left_rotate(tree, x->p);
                w = x->p->right;
            }
            if (w->left->color == BLACK && w->right->color == BLACK) {
                w->color = RED;
                x = x->p;
            } else {
                if (w->right->color == BLACK) {
                    w->left->color = BLACK;
                    w->color = RED;
                    right_rotate(tree, w);
                    w = x->p->right;
                }
                w->color = x->p->color;
                x->p->color = BLACK;
                w->right->color = BLACK;
                left_rotate(tree, x->p);
                x = tree->root;
            }
        } else {
            node_t *w = x->p->left;
            if (w->color == RED) {
                w->color = BLACK;
                x->p->color = RED;
                right_rotate(tree, x->p);
                w = x->p->left;
            }
            if (w->right->color == BLACK && w->left->color == BLACK) {
                w->color = RED;
                x = x->p;
            } else {
                if (w->left->color == BLACK) {
                    w->right->color = BLACK;
                    w->color = RED;
                    left_rotate(tree, w);
                    w = x->p->left;
                }
                w->color = x->p->color;
                x->p->color = BLACK;
                w->left->color = BLACK;
                right_rotate(tree, x->p);
                x = tree->root;
            }
        }
    }
    x->color = BLACK;
}

node_t *find_min(rbt_t *tree, node_t *x) {
    while (x->left != tree->NIL)
        x = x->left;
    return x;
}

void remove_meta(rbt_t *tree, node_t *z) {
    node_t *y = z, *x;
    color_t y_orig_color = y->color;
    if (z->left == tree->NIL) {
        x = z->right;
        transplant(tree, z, z->right);
    } else if (z->right == tree->NIL) {
        x = z->left;
        transplant(tree, z, z->left);
    } else {
        y = find_min(tree, z->right);
        y_orig_color = y->color;
        x = y->right;
        if (y->p == z)
            x->p = y;
        else {
            transplant(tree, y, y->right);
            y->right = z->right;
            y->right->p = y;
        }
        transplant(tree, z, y);
        y->left = z->left;
        y->left->p = y;
        y->color = z->color;
    }
    if (y_orig_color == BLACK)
        remove_meta_fixup(tree, x);
}

/* MEMORY ALLOCATOR */

typedef intptr_t word_t;
typedef node_t meta_t;
typedef rbt_t alloc_tree_t;

#define META_SIZE sizeof(meta_t)
#define SPLIT_SIZE sizeof(int) * 4

alloc_tree_t *alloc_tree;

size_t align(size_t size) {
    return (size + sizeof(word_t) - 1) & ~(sizeof(word_t) - 1);
}

meta_t *get_meta(void *ptr) {
    return (meta_t *) ptr - 1;
}

meta_t *req_space(size_t size) {
    meta_t *block = _sbrk(size + META_SIZE);
    if ((void *) block == (void *) -1) {
        perror("sbrk error");
        exit(EXIT_FAILURE);
    }
    block->left = alloc_tree->NIL;
    block->right = alloc_tree->NIL;
    block->p = alloc_tree->NIL;
    block->prev = alloc_tree->last_alloc;
    if (block->prev != alloc_tree->NIL)
        block->prev->next = block;
    block->next = alloc_tree->NIL;

    block->used = true;
    block->size = size;
    block->color = RED;
    insert_meta(alloc_tree, block);
    return block;
}

meta_t *find_free(meta_t **last, size_t size) {
    meta_t *cur = alloc_tree->root;
    while (cur != alloc_tree->NIL) {
        if (cur->size == size)
            break;
        *last = cur;
        if (cur->size < size)
            cur = cur->right;
        else
            cur = cur->left;
    }
    if (cur == alloc_tree->NIL) {
        cur = *last;
        while (cur != alloc_tree->NIL && cur->size < size)
            cur = cur->p;
    }
    return cur;
}

void split_space(meta_t *last, size_t size) {
    if (last == alloc_tree->NIL)
        return;
    remove_meta(alloc_tree, last);
    meta_t *splitted = (void *) last + META_SIZE + size;
    splitted->size = last->size - size - META_SIZE;
    splitted->used = false;
    splitted->prev = last;
    splitted->next = alloc_tree->NIL;
    last->next = splitted;
    last->size = size;
    alloc_tree->last_alloc = splitted;

    insert_meta(alloc_tree, last);
    insert_meta(alloc_tree, splitted);
}

void free_space(void *ptr) {
    if (!ptr)
        return;
    meta_t *block = get_meta(ptr);
    block->used = false;

    if (block->prev != alloc_tree->NIL && !block->prev->used) {
        remove_meta(alloc_tree, block);
        remove_meta(alloc_tree, block->prev);
        block->prev->size += (block->size + META_SIZE);
        block->prev->next = block->next;
        if (block->next)
            block->next->prev = block->prev;
        block = block->prev;
        insert_meta(alloc_tree, block);
    }

    if (block->next != alloc_tree->NIL && !block->next->used) {
        remove_meta(alloc_tree, block);
        remove_meta(alloc_tree, block->next);
        if (alloc_tree->last_alloc == block->next)
            alloc_tree->last_alloc = block;
        block->size += (block->next->size + META_SIZE);
        block->next = block->next->next;
        if (block->next)
            block->next->prev = block;
        insert_meta(alloc_tree, block);
    }
}

meta_t *alloc(size_t size) {
    if (size == 0)
        return (meta_t *) NULL;
    size = align(size);
    meta_t *allocated;
    if (alloc_tree->root == alloc_tree->NIL) {
        allocated = req_space(size);
        alloc_tree->root = allocated;
        alloc_tree->last_alloc = allocated;
    } else {
        meta_t *last = alloc_tree->root;
        allocated = find_free(&last, size);
        if (allocated == alloc_tree->NIL)
            allocated = req_space(size);
        else {
            if (allocated->size >= size + SPLIT_SIZE + META_SIZE)
                split_space(allocated, size);
            allocated->used = true;
        }
    }
    return (allocated + 1);
}

alloc_tree_t *allocator_create() {
    alloc_tree_t *allocator = _sbrk(sizeof(alloc_tree_t));
    allocator->NIL = _sbrk(sizeof(meta_t));

    allocator->NIL->left = NULL;
    allocator->NIL->right = NULL;
    allocator->NIL->p = NULL;
    allocator->NIL->prev = NULL;
    allocator->NIL->next = NULL;
    allocator->NIL->used = false;
    allocator->NIL->color = BLACK;
    allocator->NIL->size = 0;

    allocator->root = allocator->NIL;
    allocator->last_alloc = allocator->NIL;

}

void set_allocator(alloc_tree_t *t) {
    alloc_tree = t;
}

/** TEST RED-BLACK-TREE PROPERTIES **/

meta_t *create_meta(size_t size) {
    meta_t *meta = malloc(sizeof(meta_t));

    meta->prev = NULL;
    meta->next = NULL;

    meta->left = NULL;
    meta->right = NULL;
    meta->p = NULL;

    meta->color = BLACK;
    meta->used = false;
    meta->size = size;

    return meta;
}

void test_color(meta_t *node) {
    if (node == NULL)
        return;
    test_color(node->left);
    test_color(node->right);
    if (node->color == RED) {
        if (node->left)
            assert(node->left->color == BLACK);
        if (node->right)
            assert(node->right->color == BLACK);
    }
}

void test_black_amount(meta_t *node, int should_be) {
    static int count = 0;
    if (node == NULL)
        return;
    if (node->color == BLACK)
        ++count;
    test_black_amount(node->left, should_be);
    test_black_amount(node->right, should_be);
    if (!node->left && !node->right)
        assert(count == should_be);
    if (node->color == BLACK)
        --count;
}

void test_rbt_props(alloc_tree_t *tree) {
    assert(tree->root->color == BLACK);
    test_color(tree->root);

    int count = 0;
    meta_t *cur = tree->root;
    while (cur != NULL) {
        if (cur->color == BLACK)
            ++count;
        cur = cur->left;
    }
    test_black_amount(tree->root, count);
}

void test_rbt() {
    meta_t *n1, *n2, *n3, *n4, *n5, *n6;
    n1 = create_meta(41);
    n2 = create_meta(38);
    n3 = create_meta(31);
    n4 = create_meta(12);
    n5 = create_meta(19);
    n6 = create_meta(8);
    alloc_tree_t t;
    t.NIL = create_meta(0);
    t.root = t.NIL;
    insert_meta(&t, n1);
    test_rbt_props(&t);
    insert_meta(&t, n2);
    test_rbt_props(&t);
    insert_meta(&t, n3);
    test_rbt_props(&t);
    insert_meta(&t, n4);
    test_rbt_props(&t);
    insert_meta(&t, n5);
    test_rbt_props(&t);
    insert_meta(&t, n6);
    test_rbt_props(&t);
    remove_meta(&t, n6);
    test_rbt_props(&t);
    remove_meta(&t, n4);
    test_rbt_props(&t);
    remove_meta(&t, n5);
    test_rbt_props(&t);
    remove_meta(&t, n3);
    test_rbt_props(&t);
    remove_meta(&t, n2);
    test_rbt_props(&t);
    remove_meta(&t, n1);
    test_rbt_props(&t);
}

/** ============================== **/

/** TEST ALLOCATOR **/

void test_alloc() {

}

/** ============== **/

int main() {
    test_rbt();
    test_alloc();
    return 0;
}