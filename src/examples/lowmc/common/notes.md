# LowMC 开发笔记

## CBitVector

- CBitVector 作为函数参数传递时，需要通过引用传参，如 CBitVector& key。否则，参数传递将通过拷贝构造函数，同一片存储会被两个CBitVector对应共享。因此，当CBitVector 出作用域时，CBitVector的析构函数会导致同一片内存被释放两次，导致double free的错误。

