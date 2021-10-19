# Privacy-Preserving-Decision-Tree-2021 by Xiangfu, Jianli

## Network Setup

IP address is hard coded into network.h file. Default is localhost. Please change the ip address before compilation.

## Prepare
1. Clone/download the ABY repository
2. Place the dectree folder from ABY_example in ABY/src/examples and add the line
`add_subdirectory(dtree)`


## Preprecessing of FSS
```bash
./configure
make
./fss-test
```

## Compile
going to the directory /ABY
```bash
mkdir -p build
cd build
cmake .. -DABY_BUILD_EXE=On
make
```

## Run
to use lowmc: 
```
./lowmc_nonmpc
```
will generate required parameters by lowmc, 
more info see: https://eprint.iacr.org/2016/687
only to test lowmc: 
```
./lowmc_test -r 0 -t 128 -k 80 -m 31 -o 12 
```
Two terminal
```./test -r 0```
```./test -r 1```

## Tips
1.how to generate a dot file without any useless information like position when training a tree:

```
in python
    >>> clf = tree.DecisionTreeClassifier()
    >>> iris = load_iris()

    >>> clf = clf.fit(iris.data, iris.target)
    >>> tree.export_graphviz(clf, out_file = "iris.dot")
```

2.how to get a visial tree from a .dot file:  
```
dot wine -T png -o wine.png
```

3.how to simulate different networks:

LAN, RTT:0.1ms, 1Gbps  
```
sudo tc qdisc add dev lo root netem delay 0.04ms rate 1024mbit
``` 
MAN, RTT:6ms, 100Mbps  
```
sudo tc qdisc add dev lo root netem delay 3ms rate 100mbit
```  
WAN, RTT:80ms, 40Mbps  
```
sudo tc qdisc add dev lo root netem delay 40ms rate 40mbit
```  
ping localhost to see RTT  
```
ping localhost -c 6
```
delete simulated configuration: (must delete the old one before setting new simulation)   
```
sudo tc qdisc delete dev lo root netem delay 0.04ms rate 1024mbit
```
pdf crop
'pdfcrop [options] input.pdf output.pdf' call 'pdfcrop --help' for more information

## Repositories
EMP
https://github.com/emp-toolkit

ABY
https://github.com/encryptogroup/ABY

SoK: Modular and Efficient Private Decision Tree Evaluation
https://github.com/encryptogroup/PDTE 

Non-interactive and Output Expressive Private Comparison from Homomorphic Encryption
https://github.com/fionser/PrivateDecisionTree 

Towards Secure and Efficient Outsourcing of Machine Learning Classification
https://github.com/patrickwang96/Privacy-Preserving-Decision-Tree-2019

Efficient and Private Scoring of Decision Trees, Support Vector Machines and Logistic Regression Models Based on Pre-Computation
https://bitbucket.org/uwtppml/lynx/src/master/

libfss
https://github.com/frankw2/libfss.git
