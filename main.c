/**
 * MEMORY ALLOCATOR BASED ON RED-BLACK TREE
 * COMPLEXITY:
 *     1) Allocation: O(log(L)), L - number of freed blocks
 *     1) Freeing: O(log(L)),    L - number of freed blocks
 * FEATURES:
 *     1) Alignment
 *     2) Merging space
 *     3) Splitting space
 *     4) Best-fit search
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>

/**
 * CUSTOM SBRK
 */

void *arena;
void *_brk = NULL;
const size_t arena_size = 4 * 1024 * 1024;

void *_sbrk(size_t size) {
    if (!arena) {
        arena = mmap(NULL, arena_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (arena == (void *)-1) {
            perror("mmap error");
            exit(EXIT_FAILURE);
        }
        _brk = arena;
    }
    if (size == 0)
        return _brk;
    if (_brk + size >= arena + arena_size)
        return (void *)-1;
    _brk += size;
    return (_brk - size);
}

/**
 * RED-BLACK TREE
 */

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
    node_t *first_alloc;
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

/**
 * ALLOCATOR
 */

typedef intptr_t word_t;
typedef node_t meta_t;
typedef rbt_t alloc_tree_t;

#define META_SIZE sizeof(meta_t)
#define SPLIT_SIZE sizeof(int) * 8

alloc_tree_t *alloc_tree;

size_t align(size_t size) {
    return (size + sizeof(word_t) - 1) & ~(sizeof(word_t) - 1);
}

meta_t *get_meta(void *ptr) {
    return (meta_t *) ptr - 1;
}

meta_t *req_space(size_t size) {
    meta_t *block = _sbrk(size + META_SIZE);

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
    alloc_tree->last_alloc = block;
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

    insert_meta(alloc_tree, splitted);
}

void free_space(void *ptr) {
    if (!ptr)
        return;
    meta_t *block = get_meta(ptr);
    block->used = false;
    insert_meta(alloc_tree, block);

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

void *alloc(size_t size) {
    if (size == 0)
        return (meta_t *) NULL;
    size = align(size);
    meta_t *allocated;
    if (alloc_tree->first_alloc == alloc_tree->NIL) {
        allocated = req_space(size);
        alloc_tree->first_alloc = allocated;
        alloc_tree->last_alloc = allocated;
    } else {
        meta_t *last = alloc_tree->root;
        allocated = find_free(&last, size);
        if (allocated == alloc_tree->NIL)
            allocated = req_space(size);
        else {
            if (allocated->size >= size + SPLIT_SIZE + META_SIZE)   // if can be splitted
                split_space(allocated, size);
            else
                remove_meta(alloc_tree, allocated);
            allocated->used = true;
        }
    }
    return (allocated + 1);
}

void *create_allocator() {
    alloc_tree = _sbrk(sizeof(alloc_tree_t));
    alloc_tree->NIL = _sbrk(sizeof(meta_t));

    alloc_tree->NIL->left = NULL;
    alloc_tree->NIL->right = NULL;
    alloc_tree->NIL->p = NULL;
    alloc_tree->NIL->prev = NULL;
    alloc_tree->NIL->next = NULL;
    alloc_tree->NIL->used = false;
    alloc_tree->NIL->color = BLACK;
    alloc_tree->NIL->size = 0;

    alloc_tree->root = alloc_tree->NIL;
    alloc_tree->first_alloc = alloc_tree->NIL;
    alloc_tree->last_alloc = alloc_tree->NIL;
}

void *destroy_allocator() {
    munmap(arena, arena_size);
    arena = NULL;
    _brk = NULL;
}

int main() {
    {
        create_allocator();
        int *arr = alloc(10 * sizeof(int));
        assert(alloc_tree->root == alloc_tree->NIL);
        int *arr2 = alloc(20 * sizeof(int));
        assert(alloc_tree->root == alloc_tree->NIL);
        assert(alloc_tree->first_alloc == get_meta(arr));
        assert(alloc_tree->last_alloc == get_meta(arr2));
        free_space(arr);
        assert(alloc_tree->root == get_meta(arr));
        assert(alloc_tree->root->size == 10 * sizeof(int));
        free_space(arr2);
        assert(alloc_tree->root == get_meta(arr));
        assert(alloc_tree->root->size == 10 * sizeof(int) + META_SIZE + 20 * sizeof(int));
        destroy_allocator();
    }
    {
        create_allocator();
        int *arr = alloc(10 * sizeof(int));
        int *arr2 = alloc(10 * sizeof(int));
        int *arr3 = alloc(10 * sizeof(int));
        int *arr4 = alloc(10 * sizeof(int));
        free_space(arr2);
        free_space(arr4);
        assert(alloc_tree->root == get_meta(arr2));
        assert(alloc_tree->root->right == get_meta(arr4));
        free_space(arr3);
        assert(alloc_tree->root->size == (10 * sizeof(int)) * 3 + 2 * META_SIZE);
        assert(alloc_tree->root->left == alloc_tree->NIL);
        assert(alloc_tree->root->right == alloc_tree->NIL);
        free_space(arr);
        destroy_allocator();
    }
    {
        create_allocator();
        int *arr = alloc(1000 * sizeof(int));
        free_space(arr);
        int *arr2 = alloc(500 * sizeof(int));        // should split
        assert(alloc_tree->root->size == 1000 * sizeof(int) - 500 * sizeof(int) - META_SIZE);
        free_space(arr2);
        int *arr3 = alloc(1000 * sizeof(int) - SPLIT_SIZE); // should not split
        assert(alloc_tree->root == alloc_tree->NIL);
        free_space(arr3);
        destroy_allocator();
    }
    return 0;
}