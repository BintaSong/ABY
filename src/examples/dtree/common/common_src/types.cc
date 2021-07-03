#include "types.h"

#include "utils.h"
#include "secret_sharing.h"
//#include <bits/stdint-intn.h>

extern gmp_randclass gmp_prn;

triplet_bit::triplet_bit()
{
  u = mod_bit(rand());
  g = mod_bit(rand());
  z = mod_bit(u*g);

  ss_encrypt(u, us);
  ss_encrypt(g, gs);
  ss_encrypt(z, zs);
}

triplet_mpz::triplet_mpz()
{
  u = gmp_prn.get_z_bits(CONFIG_L);
  g = gmp_prn.get_z_bits(CONFIG_L);
  z = u*g;
  mod_2exp(z, CONFIG_L);

  ss_encrypt(u, us);
  ss_encrypt(g, gs);
  ss_encrypt(z, zs);
}


triplet_m::triplet_m()
{
}

triplet_m::triplet_m(int X_row, int X_col, int Y_col)
: X(X_row, X_col),
  Y(X_col, Y_col),
  Z(X_row, Y_col) 
{
	// no need for shares
	matrix_rand_2exp(X, CONFIG_L);
	matrix_rand_2exp(Y, CONFIG_L);
	Z = X*Y;
  mod_2exp(Z, CONFIG_L);
}

triplet_m::triplet_m(int n)
: X(n, 1),
  Y(n, 1),
  Z(n, 1)
{
	// no need for shares
	matrix_rand_2exp(X, CONFIG_L);
	matrix_rand_2exp(X, CONFIG_L);
	Z = X.array()*Y.array();
  mod_2exp(Z, CONFIG_L);
}

ss_tuple::ss_tuple(int nrow, int ncol)
: plain(nrow, ncol),
  share{ matrix_z(nrow, ncol), matrix_z(nrow, ncol) }
{
}

ss_tuple::ss_tuple(matrix_z& plaintext, matrix_z sharetext[2]){
	plain = plaintext;
	share[0] = sharetext[0];
	share[1] = sharetext[1];
}

ss_tuple::ss_tuple(matrix_z &plaintext, int nrow, int ncol)
: share{ matrix_z(nrow, ncol), matrix_z(nrow, ncol)}{
	plain = plaintext;
}

ss_tuple::ss_tuple()
{
}

ss_tuple::ss_tuple(const ss_tuple & s)
{
	*this = s;
}

ss_tuple & ss_tuple::operator=(const ss_tuple & rhs)
{
	plain = rhs.plain;
	share[0] = rhs.share[0];
	share[1] = rhs.share[1];

	return *this;
}

void ss_tuple::init(){
	matrix_rand_2exp(plain, CONFIG_L);
}

void ss_tuple::init128(){
	matrix_rand_2exp(plain, CONFIG_C);
}
void ss_tuple::encrypt() 
{
	ss_encrypt(plain, share);
}

void ss_tuple::decrypt() 
{
	ss_decrypt(plain, share);
}

void ss_tuple::encrypt_xor() 
{
	ss_encrypt_xor(plain, share);
}

void ss_tuple::decrypt_xor() 
{
	ss_decrypt_xor(plain, share);
}

void ss_tuple::reset()
{
    plain.setZero();
    share[0].setZero();
    share[1].setZero();
}

node_tuple::node_tuple()
{
}

node_tuple::node_tuple(int nrow, int ncol)
: plain(nrow, ncol)
{
}

node_tuple::node_tuple(matrix_z& plaintext){
	plain = plaintext;
}

node_tuple::node_tuple(matrix_z &plaintext, int nrow, int ncol)
{
	plain = plaintext;
}

node_tuple::node_tuple(const node_tuple & s)
{
	*this = s;
}

node_tuple & node_tuple::operator=(const node_tuple & rhs)
{
	plain = rhs.plain;
	return *this;
}

void node_tuple::init(){
	matrix_rand_2exp(plain, CONFIG_L);
}

void node_tuple::init128(){
	matrix_rand_2exp(plain, CONFIG_C);
}

void node_tuple::reset()
{
    plain.setZero();
}




tri_tuple::tri_tuple(int X_row, int X_col, int Y_col)
: plain(X_row, X_col, Y_col),
  share{triplet_mz(X_row, X_col, Y_col) , triplet_mz(X_row, X_col, Y_col)}
{
}

tri_tuple::tri_tuple(int n)
: plain(n),
  share{ triplet_mz(n), triplet_mz(n) }
{
}

tri_tuple::tri_tuple()
{
}

tri_tuple::tri_tuple(const tri_tuple &t)
{
	*this = t;
}

tri_tuple & tri_tuple::operator=(const tri_tuple &rhs)
{
	plain = rhs.plain;
	share[0] = rhs.share[0];
	share[1] = rhs.share[1];

	return *this;
}

void tri_tuple::encrypt() 
{
	ss_encrypt(plain.X, share[0].X, share[1].X);
	ss_encrypt(plain.Y, share[0].Y, share[1].Y);
	ss_encrypt(plain.Z, share[0].Z, share[1].Z);
}

void tri_tuple::decrypt() 
{
	ss_decrypt(plain.X, share[0].X, share[1].X);
	ss_decrypt(plain.Y, share[0].Y, share[1].Y);
	ss_decrypt(plain.Z, share[0].Z, share[1].Z);
}