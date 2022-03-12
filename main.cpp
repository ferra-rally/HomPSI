#include <iostream>
#include "examples.h"
#include "protoBuff/ciphertexts.pb.h"

using namespace seal;
using namespace std;

vector<string> read_csv(const string &filename) {
    ifstream file(filename.c_str());

    vector<string> rows;
    if(file.is_open()) {
        string line;

        while (getline(file, line)) {
            rows.emplace_back(line.c_str());
        }

        file.close();
    }

    return rows;
}

SEALContext generate_context(const string& out_params_filename, int poly_modulus, int plain_modulus) {
    //Prepare parameters
    EncryptionParameters parms(scheme_type::bfv);

    //    Larger poly_modulus_degree makes ciphertext sizes larger and all operations
    //    slower, but enables more complicated encrypted computations. Recommended
    //    values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
    //    to go beyond this range.

    size_t poly_modulus_degree = poly_modulus;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    //        +----------------------------------------------------+
    //        | poly_modulus_degree | max coeff_modulus bit-length |
    //        +---------------------+------------------------------+
    //        | 1024                | 27                           |
    //        | 2048                | 54                           |
    //        | 4096                | 109                          |
    //        | 8192                | 218                          |
    //        | 16384               | 438                          |
    //        | 32768               | 881                          |
    //        +---------------------+------------------------------+

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(plain_modulus);

    SEALContext context(parms);

    ofstream parmsFile;
    parmsFile.open(out_params_filename);
    parms.save(parmsFile);

    parmsFile.close();

    print_parameters(context);

    return context;
}

SEALContext get_context_from_file(const string& params_filename) {
    EncryptionParameters parms(scheme_type::bfv);
    ifstream parmsFile;
    parmsFile.open(params_filename);
    if(!parmsFile.is_open()) {
        cerr << "Failed to open parameters" << endl;
        exit(-1);
    }

    parms.load(parmsFile);

    SEALContext context(parms);
    parmsFile.close();

    return context;
}

void setup(const string& params_filename, const string& sec_key_filename, const string& pub_key_filename, const string& relin_key_filename, int poly_modulus, int plain_modulus) {
    SEALContext context = generate_context(params_filename, poly_modulus, plain_modulus);

    cout << "Params file: " << params_filename << endl;
    cout << "Pub Key file: " << pub_key_filename << endl;
    cout << "Sec Key file: " << sec_key_filename << endl;
    cout << "Relinearization key file: " << relin_key_filename << endl;

    //Setup keys
    //Generate Keys
    KeyGenerator keygen(context);
    const SecretKey &secret_key = keygen.secret_key();

    PublicKey public_key;

    keygen.create_public_key(public_key);

    RelinKeys relinKeys;
    keygen.create_relin_keys(relinKeys);

    //Saving keys
    ofstream pubkeyfile;
    ofstream seckeyfile;
    ofstream relkeyfile(relin_key_filename);

    pubkeyfile.open(pub_key_filename);
    seckeyfile.open(sec_key_filename);

    public_key.save(pubkeyfile);
    secret_key.save(seckeyfile);
    relinKeys.save(relkeyfile);

    pubkeyfile.close();
    seckeyfile.close();
    relkeyfile.close();
}

string convert_to_hex(const string& input) {
    string out_string;

    for(char c : input) {
        out_string.append(uint64_to_hex_string(c));
    }

    return out_string;
}

int encrypt(const string &pub_key_filename, const string &csv_filename, const string &out_filename, const string &params_filename) {
    SEALContext context = get_context_from_file(params_filename);
    PublicKey public_key;

    cout << "Key file: " << pub_key_filename << endl;
    cout << "Params file: " << params_filename << endl;
    cout << "CSV file: " << csv_filename << endl;
    cout << "Out PB file: " << out_filename << endl;

    ifstream pub_key_stream;
    pub_key_stream.open(pub_key_filename);
    if(!pub_key_stream.is_open()) {
        cerr << "Public key file not found" << endl;

        return -1;
    }
    public_key.load(context, pub_key_stream);
    pub_key_stream.close();

    vector<string> rows = read_csv(csv_filename);
    if(rows.empty()) {
        cerr << "Could not open csv file" << endl;
        return -1;
    }

    Encryptor encryptor(context, public_key);

    HomPSI::Ciphertexts out_protocol_buffer = HomPSI::Ciphertexts();

    print_parameters(context);

    Ciphertext c;

    cout << "Starting encryption of " << rows.size() << " elements..." << endl;

    int bar_width = 70;
    float progress;
    auto size = float(rows.size());

    for (int i = 0; i < rows.size(); i++) {
        string row = rows[i];

        string line = convert_to_hex(row);

        Plaintext plaintext(line);
        encryptor.encrypt(plaintext, c);

        //Serialize Ciphertexts and save them in a protocol buffer
        stringstream cipher_stream;
        c.save(cipher_stream);

        string serialized_ciphertext = cipher_stream.str();

        out_protocol_buffer.add_ciphertexts(serialized_ciphertext);

        progress = float(i)/size;

        // Progress bar
        std::cout << "[";
        int pos = float(bar_width) * progress;
        for (int j = 0; j < bar_width; ++j) {
            if (j < pos) std::cout << "=";
            else if (j == pos) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << int(progress * 100.0) << " %\r";
        std::cout.flush();
    }

    std::cout << std::endl;


    cout << "Encryption done..." << endl;

    cout << "Generating output file: " << out_filename << endl;
    ofstream out_file(out_filename);
    out_protocol_buffer.SerializeToOstream(&out_file);
    out_file.close();

    return 0;
}

int inter(const string &pub_key_filename, const string &csv_filename, const string &in_protocol_buffer_filename, const string &out_protocol_buffer_filename, const string &relin_key_filename, const string &params_filename) {
    SEALContext context = get_context_from_file(params_filename);
    Evaluator evaluator(context);
    PublicKey public_key;
    RelinKeys relin_key;

    HomPSI::Ciphertexts in_protocol_buffer = HomPSI::Ciphertexts();
    HomPSI::Ciphertexts out_protocol_buffer = HomPSI::Ciphertexts();

    print_parameters(context);

    cout << "Key file: " << pub_key_filename << endl;
    cout << "Relinearization key file: " << relin_key_filename << endl;
    cout << "Params file: " << params_filename << endl;
    cout << "CSV file: " << csv_filename << endl;
    cout << "In PB file: " << in_protocol_buffer_filename << endl;
    cout << "Out PB file: " << out_protocol_buffer_filename << endl;

    //Load keys
    ifstream pub_key_stream;
    pub_key_stream.open(pub_key_filename);
    if(!pub_key_stream.is_open()) {
        cerr << "Public key file not found" << endl;
        return -1;
    }

    public_key.load(context, pub_key_stream);
    pub_key_stream.close();
    ifstream relin_stream(relin_key_filename);
    if(!relin_stream.is_open()) {
        cerr << "Relin key file not found" << endl;
        return -1;
    }

    relin_key.load(context, relin_stream);
    relin_stream.close();

    Encryptor encryptor(context, public_key);

    //Read sender csv file
    vector<string> csvRows = read_csv(csv_filename);
    if(csvRows.empty()) {
        cerr << "Could not open csv file" << endl;
        return -1;
    }

    //Initialize random number generator

    ifstream in_protocol_buffer_stream(in_protocol_buffer_filename);
    if(!in_protocol_buffer_stream.is_open()) {
        cerr << "Input protocol buffer file not found" << endl;
        return -1;
    }

    in_protocol_buffer.ParseFromIstream(&in_protocol_buffer_stream);

    vector<Ciphertext> sender_ciphertexts;
    vector<Ciphertext> out_ciphertexts;

    for(auto &row: csvRows) {
        Plaintext p(convert_to_hex(row));
        Ciphertext c;

        encryptor.encrypt(p, c);
        sender_ciphertexts.push_back(c);
    }

    auto serialized_ciphertexts = in_protocol_buffer.ciphertexts();
    vector<Ciphertext> in_ciphertexts;
    stringstream ss;
    Ciphertext c;

    for(int i = 0; i < serialized_ciphertexts.size(); i++) {
        ss << serialized_ciphertexts.Get(i);

        c.load(context, ss);

        in_ciphertexts.push_back(c);
    }

    cout << "Receiver N: " << in_ciphertexts.size() << " Sender N: " << sender_ciphertexts.size() << endl;

    int bar_width = 70;
    float progress;
    auto size = float(in_ciphertexts.size());

    for(int i = 0; i < in_ciphertexts.size(); i++) {
        Ciphertext in_ciphertext = in_ciphertexts[i];
        Plaintext p(uint64_to_hex_string(random_uint64() + 1));
        Ciphertext res;
        vector<Ciphertext> partials;

        encryptor.encrypt(p, res);


        for(auto &s_ciphertext : sender_ciphertexts) {
            Ciphertext diff;
            evaluator.sub(in_ciphertext, s_ciphertext, diff);

            evaluator.multiply_inplace(res, diff);
            evaluator.relinearize_inplace(res, relin_key);
        }

        out_ciphertexts.push_back(res);

        //Serialize Ciphertexts and save them in a protocol buffer
        stringstream ciphers_stream;
        res.save(ciphers_stream);

        string serialized_ciphertext = ciphers_stream.str();
        out_protocol_buffer.add_ciphertexts(serialized_ciphertext);

        progress = float(i)/size;

        // Progress bar
        std::cout << "[";
        int pos = float(bar_width) * progress;
        for (int j = 0; j < bar_width; ++j) {
            if (j < pos) std::cout << "=";
            else if (j == pos) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << int(progress * 100.0) << " %\r";
        std::cout.flush();
    }

    std::cout << std::endl;

    cout << "Intersection done...saving to " << out_protocol_buffer_filename  << endl;

    ofstream out_ciphertexts_stream(out_protocol_buffer_filename);
    out_protocol_buffer.SerializeToOstream(&out_ciphertexts_stream);
    out_ciphertexts_stream.close();

    cout << "Done calculating..." << endl;

    return 0;
}

int receive(const string &sec_key_filename, const string &csv_filename, const string &in_protocol_buffer_filename, const string &intersection_filename, const string& params_filename) {
    SEALContext context = get_context_from_file(params_filename);

    print_parameters(context);

    cout << "Key file: " << sec_key_filename << endl;
    cout << "Params file: " << params_filename << endl;
    cout << "CSV file: " << csv_filename << endl;
    cout << "In PB file: " << in_protocol_buffer_filename << endl;
    cout << "Out CSV file: " << intersection_filename << endl;

    //Load secret key
    SecretKey secretKey;
    ifstream secKeyStream;

    secKeyStream.open(sec_key_filename);
    secretKey.load(context, secKeyStream);
    secKeyStream.close();
    cout << "Loaded key" << endl;

    Decryptor decryptor(context, secretKey);
    HomPSI::Ciphertexts buff = HomPSI::Ciphertexts();

    ifstream file(in_protocol_buffer_filename.c_str());
    buff.ParseFromIstream(&file);
    auto b = buff.ciphertexts();

    cout << "Loaded results" << endl;
    vector<string> rows;

    rows.reserve(b.size());
    for (int i = 0; i < b.size(); i++) {
        rows.push_back(b.Get(i));
    }

    vector<string> csvRows = read_csv(csv_filename);
    if(csvRows.empty()) {
        cerr << "Could not open csv file" << endl;
        return -1;
    }

    stringstream ss;

    ofstream intersection_stream(intersection_filename);

    for (int i = 0; i < rows.size(); i++) {
        ss << rows[i];

        Ciphertext ciphertext;
        Plaintext plaintext;

        ciphertext.load(context, ss);


        if(decryptor.invariant_noise_budget(ciphertext) == 0) {
            cout << "No more noise budget for " << csvRows[i] << endl;
            continue;
        }

        decryptor.decrypt(ciphertext, plaintext);

        if(plaintext.to_string() == "0") {
            cout << "Match for " << csvRows[i] << endl;
        }

        intersection_stream << csvRows[i] << endl;
    }

    intersection_stream.close();

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cout << "Wrong usage, use command help to see list of commands";

        return -1;
    }

    string command = argv[1];
    if (command == "help") {
        cout << "Commands:\n"
                "\tsetup: setup keys for the receiver and generates key files\n"
                "\thelp: prints list of commands\n"
                "\tencrypt <pubkey> <csv file to encrypt> <out csv>: crypt a series of bitstrings of the same lenght\n"
                "\tinter <pubkey> <own csv file> <target csv>\n"
                "\treceive <seckey> <own csv file> <received file>\n";

        return 0;
    } else if (command == "setup") {
        string pub_key_filename = "pub.key";
        string sec_key_filename = "sec.key";
        string params_filename = "params.par";
        string relin_key_filename = "relin.key";
        int plain_modulus = 1024;
        int poly_modulus = 8192;

        if(argc >= 2) {
            for (int i = 2; i < argc; ++i) {
                if(!strcmp(argv[i], "-k") && argc > i + 1) {
                    pub_key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-s") && argc > i + 1) {
                    sec_key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-p") && argc > i + 1) {
                    params_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-r") && argc > i + 1) {
                    relin_key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-y") && argc > i + 1) {
                    poly_modulus = stoi(argv[i + 1]);
                    i++;
                } else if(!strcmp(argv[i], "-l") && argc > i + 1) {
                    plain_modulus = stoi(argv[i + 1]);
                    i++;
                }
            }
        } else if(argc == 1) {
            cout << "Wrong number of parameters";

            return -1;
        }

        setup(params_filename, sec_key_filename, pub_key_filename, relin_key_filename, poly_modulus, plain_modulus);
    } else if (command == "encrypt") {
        string key_filename = "pub.key";
        string csv_filename = "receiver.csv";
        string out_filename = "receiver.pb";
        string params_filename = "params.par";

        if(argc >= 2) {
            for (int i = 2; i < argc; ++i) {
                if(!strcmp(argv[i], "-k") && argc > i + 1) {
                    key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-i") && argc > i + 1) {
                    csv_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-o") && argc > i + 1) {
                    out_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-p") && argc > i + 1) {
                    params_filename = argv[i + 1];
                    i++;
                }
            }
        } else if(argc == 1) {
            cout << "Wrong number of parameters";

            return -1;
        }

        encrypt(key_filename, csv_filename, out_filename, params_filename);
    } else if (command == "inter") {
        string key_filename = "pub.key";
        string csv_filename = "sender.csv";
        string out_filename = "sender.pb";
        string params_filename = "params.par";
        string relin_key_filename = "relin.key";
        string in_pb_filename = "receiver.pb";

        if(argc >= 2) {
            for (int i = 2; i < argc; ++i) {
                if(!strcmp(argv[i], "-k") && argc > i + 1) {
                    key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-i") && argc > i + 1) {
                    csv_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-o") && argc > i + 1) {
                    out_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-p") && argc > i + 1) {
                    params_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-r") && argc > i + 1) {
                    relin_key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-b") && argc > i + 1) {
                    in_pb_filename = argv[i + 1];
                    i++;
                }
            }
        } else if(argc == 1) {
            cout << "Wrong number of parameters";

            return -1;
        }

        inter(key_filename, csv_filename, in_pb_filename, out_filename, relin_key_filename, params_filename);
    } else if (command == "receive") {
        string key_filename = "sec.key";
        string csv_filename = "receiver.csv";
        string out_filename = "intersection.csv";
        string params_filename = "params.par";
        string in_pb_filename = "sender.pb";

        if(argc >= 2) {
            for (int i = 2; i < argc; ++i) {
                if(!strcmp(argv[i], "-k") && argc > i + 1) {
                    key_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-i") && argc > i + 1) {
                    csv_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-o") && argc > i + 1) {
                    out_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-p") && argc > i + 1) {
                    params_filename = argv[i + 1];
                    i++;
                } else if(!strcmp(argv[i], "-b") && argc > i + 1) {
                    in_pb_filename = argv[i + 1];
                    i++;
                }
            }
        } else if(argc == 1) {
            cout << "Wrong number of parameters";

            return -1;
        }

        receive(key_filename, csv_filename, in_pb_filename, out_filename, params_filename);
    }

    return 0;
}