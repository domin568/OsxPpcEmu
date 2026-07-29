/*
 * thunk_test.cpp
 *
 * Compile with Metrowerks CodeWarrior for PPC:
 *   mwcppc -c thunk_test.cpp -o thunk_test.o
 *
 * This produces thunk code entries in the .o file for every virtual
 * method override accessed through a non-primary base pointer.
 * Load thunk_test.o in IDA Pro with mwobppc_ida.py to inspect them.
 */

/* ── Case 1: Simple this-adjustment thunk (12 bytes) ─────────────
 *
 *   B is the non-primary base of C.  Calling C::Foo() through a B*
 *   requires subtracting sizeof(A) from 'this' to get back to C*.
 *   The compiler emits:
 *       addi  r3, r3, -4      ; adjust this (sizeof A vptr = 4)
 *       lwz   r12, 0(r2)      ; load target descriptor from TOC
 *       b     .__ptr_glue      ; 0x48000000 placeholder
 */
class A1 {
public:
    virtual void VirtA() {}
};

class B1 {
public:
    virtual void Foo() {}
};

class C1 : public A1, public B1 {
public:
    void Foo() {}  /* thunk needed: B1* → C1* adjustment */
};

C1 g_c1;  /* force vtable emission */


/* ── Case 2: Larger this-adjustment (12 bytes, bigger offset) ────
 *
 *   More data members in the primary base → larger this-offset.
 *       addi  r3, r3, -20
 *       lwz   r12, 0(r2)
 *       b     .__ptr_glue
 */
class Base2 {
public:
    virtual void Dummy() {}
    int data[4];  /* 16 bytes of data + 4 byte vptr = 20 byte offset */
};

class Iface2 {
public:
    virtual void DoWork() {}
};

class Derived2 : public Base2, public Iface2 {
public:
    void DoWork() {}  /* thunk: Iface2* → Derived2*, offset = -20 */
};

Derived2 g_d2;


/* ── Case 3: Multiple thunks from one class ──────────────────────
 *
 *   Overriding several methods from a non-primary base generates
 *   one thunk per overridden method.
 */
class Primary3 {
public:
    virtual void P() {}
};

class Secondary3 {
public:
    virtual void X() {}
    virtual void Y() {}
    virtual void Z() {}
};

class Multi3 : public Primary3, public Secondary3 {
public:
    void X()  {}  /* thunk for Secondary3::X */
    void Y()  {}  /* thunk for Secondary3::Y */
    void Z()  {}  /* thunk for Secondary3::Z */
};

Multi3 g_m3;


/* ── Case 4: Diamond with virtual inheritance ────────────────────
 *
 *   Virtual inheritance may produce thunks with vcall-offset
 *   (virtual this-adjustment), generating larger thunk bodies
 *   that load through the vtable to compute the this-delta.
 */
class VBase4 {
public:
    virtual void Action() {}
};

class Left4 : virtual public VBase4 {
public:
    int left_data;
};

class Right4 : virtual public VBase4 {
public:
    int right_data;
    void Action()  {}
};

class Diamond4 : public Left4, public Right4 {
public:
    void Action()  {}  /* may need vcall thunk */
};

Diamond4 g_d4;


/* ── Case 5: Deep hierarchy, non-primary at multiple levels ──────
 *
 *   Forces the compiler to emit thunks at different depths.
 */
class IfaceA5 {
public:
    virtual void Step() {}
};

class IfaceB5 {
public:
    virtual void Step() {}
};

class MidA5 : public IfaceA5 {
public:
    virtual void Extra() {}
    int pad[2];
};

class MidB5 : public IfaceB5 {
public:
    void Step() {}
};

class Final5 : public MidA5, public MidB5 {
public:
    void Step() {}  /* thunks for both IfaceA5 and MidB5 paths */
};

Final5 g_f5;