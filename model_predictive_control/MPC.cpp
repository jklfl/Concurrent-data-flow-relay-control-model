#include "MPC.hpp"

namespace plt = matplotlibcpp;



Eigen::VectorXd RunMPC(unsigned int N, Eigen::VectorXd &init_x, Eigen::MatrixXd &A, Eigen::MatrixXd &B,
                       Eigen::MatrixXd &Q, Eigen::MatrixXd &R, Eigen::MatrixXd &F) {

    unsigned int num_state = init_x.rows();
    unsigned int num_control = B.cols();

    Eigen::MatrixXd C, M;
    C.resize((N + 1) * num_state, num_control * N);
    C.setZero();
    M.resize((N + 1) * num_state, num_state);
    Eigen::MatrixXd temp;
    temp.resize(num_state, num_state);
    temp.setIdentity();
    M.block(0, 0, num_state, num_state).setIdentity();
    for (unsigned int i = 1; i <= N; ++i) {
        Eigen::MatrixXd temp_c;
        temp_c.resize(num_state, (N + 1) * num_control);
        temp_c << temp * B, C.block(num_state * (i - 1), 0, num_state, C.cols());

        C.block(num_state * i, 0, num_state, C.cols())
                = temp_c.block(0, 0, num_state, temp_c.cols() - num_control);

        temp = A * temp;
        M.block(num_state * i, 0, num_state, num_state) = temp;
    }

    Eigen::MatrixXd Q_bar, R_bar;

    Q_bar.resize(num_state * (N + 1), num_state * (N + 1));
    Q_bar.setZero();
    for (unsigned int i = 0; i < N; ++i) {
        Q_bar.block(num_state * i, num_state * i, num_state, num_state) = Q;
    }
    Q_bar.block(num_state * N, num_state * N, num_state, num_state) = F;

    R_bar.resize(N * num_control, N * num_control);
    R_bar.setZero();
    for (unsigned int i = 0; i < N; ++i) {
        R_bar.block(i * num_control, i * num_control, num_control, num_control) = R;
    }

    Eigen::MatrixXd G = M.transpose() * Q_bar * M;
    Eigen::MatrixXd E = C.transpose() * Q_bar * M;
    Eigen::MatrixXd H = C.transpose() * Q_bar * C + R_bar;
    
    Eigen::VectorXd c_x;
    c_x.resize(2, 1);
    c_x << 8, 0.0;
    c_x[0] = init_x[0] - c_x[0];
    c_x[1] = init_x[1] - c_x[1];

    return H.inverse() * (-E * c_x);
}

int MPC(int len) {
    Eigen::MatrixXd A, B;
    A.resize(2, 2);
    B.resize(2, 1);
    A << 1, 0.1, 0, 0;
    B << 0, 0.5;

    unsigned int num_state = 2;

    Eigen::MatrixXd Q, R, F;
    Q.resize(num_state, num_state);
    Q << 1, 0, 0, 1;

    R.resize(1, 1);
    R << 0.1;

    F.resize(num_state, num_state);
    F << len, 0, 0, len;

    std::vector<long long> res;
    std::string line;
    std::string file_path = "/root/mpc/algorithm_learning-main/model_predictive_control/8over.txt";
    std::string out_path = "/root/mpc/algorithm_learning-main/model_predictive_control/M_out.txt";
    std::ifstream file(file_path);
    std::ofstream o_file(out_path);
    while(std::getline(file, line)){
	    long long value = std::stoll(line);
	    const unsigned int N = 3;
	    Eigen::VectorXd init_x;
	    init_x.resize(2, 1);
	    init_x << value, 0.0;

	    std::cout << value << std::endl;

	    std::vector<long long> state_0;
	    std::vector<double> time;
	    state_0.emplace_back(init_x.x());
	    time.emplace_back(0.0);

	    for (unsigned int i = 0; i < 130; ++i) {
		//std::cout << "error: " << init_x.transpose() << std::endl;
		std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();
		Eigen::VectorXd control = RunMPC(N, init_x, A, B, Q, R, F);
		std::chrono::steady_clock::time_point end_time = std::chrono::steady_clock::now();
		std::chrono::duration<double> used_time = (end_time - start_time);
		//std::cout << "Once mpc use time(ms): " << used_time.count() * 1000 << std::endl;
		init_x = A * init_x + B * control.x();
		state_0.emplace_back(init_x.x());
		time.emplace_back(0.1 * (i + 1));
	    }
	   
           res.emplace_back(state_0[129]);
	   //std::cout << state_0[399] << std::endl;
           o_file << state_0[129] << std::endl;
   } 
   file.close();
//    std::cout << "closed form u: " << control.transpose() << std::endl;

    return 0;
}
