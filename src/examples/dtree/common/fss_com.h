#ifndef FSS_COM_H
#define FSS_COM_H

#include "../fss/fss-common.h"
#include "../fss/fss-client.h"
#include "../fss/fss-server.h"
#include <cmath>
#include <vector>

void fssKeyGen(ServerKeyEq &k0, ServerKeyEq &k1, uint64_t a, Fss& fClient, Fss& fServer);
vector<int> fssEvaluate(ServerKeyEq k, uint64_t ceil, uint64_t num, Fss& fClient, Fss& fServer);
#endif