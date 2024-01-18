#include <Eigen/Dense>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include "matplotlibcpp.h"
#include <chrono>

Eigen::VectorXd RunMPC(unsigned int N, Eigen::VectorXd &init_x, Eigen::MatrixXd &A, Eigen::MatrixXd &B,
                       Eigen::MatrixXd &Q, Eigen::MatrixXd &R, Eigen::MatrixXd &F);
int MPC(int len);