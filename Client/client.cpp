#include <iostream>
#include <vector>
#include <string.h> //for memset and substr()
#include <netinet/in.h> //for sockaddr_in
#include <arpa/inet.h> //functions for IP addrr manipulation: inet_pton
#include <sys/socket.h>//for socket(),connect()
#include <unistd.h>//for close()
#include <sstream> // for stringstream()
#include <thread>
#include <cstring>
#include <fcntl.h>
#include <cstdlib>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <iomanip>

using namespace std;
string tracker_ip,my_ip;
int tracker_port,my_port;
int tracker_socket,my_socket; //socket that the active tracker is binded to and this particular client_socket(my_socket)
struct sockaddr_in my_addr;
size_t chunk_size=512*1024; //512 kb

bool validate_sha_keys(vector<pair<int,string>>&gen_keys,vector<pair<int,string>>&recv_keys){
    if(gen_keys.size()!=recv_keys.size())
        return false;
    for(int i=0;i<gen_keys.size();i++){
        if(gen_keys[i].second!=recv_keys[i].second)
            return false;
    }
    return true;
}
vector<pair<size_t, size_t>> get_chunks(size_t file_size) {
    vector<pair<size_t, size_t>> chunks;
    size_t start = 0;
    while (start < file_size) {
        size_t end = min(start + chunk_size, file_size);
        chunks.push_back({start, end}); // Store (start, end) byte positions
        start = end;
    }   
    return chunks;
}

string change_to_hex(unsigned char* hash_key, size_t len){
    stringstream ss;
    ss<<hex<<setfill('0');
    for(size_t i=0;i<len;i++){
        ss<<setw(2)<<static_cast<int>(hash_key[i]);
    }
    return ss.str();
}

vector<string>  compute_sha_hash(string& file_path){

    // Get the file size
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0) {
        throw runtime_error("Failed to get file size for " + file_path + ": " + strerror(errno));
    }
    size_t file_size = st.st_size;
    // Get chunks using the provided get_chunks function
    vector<pair<size_t, size_t>> chunks = get_chunks(file_size);

    int file_dsp = open(file_path.c_str(), O_RDONLY);
    if(file_dsp < 0){
        throw runtime_error("Failed to open the file " + file_path + " to compute SHA256 key by client: " + strerror(errno));
    }

    vector<string> chunk_hashes;
    chunk_hashes.reserve(chunks.size());

    for(const auto& [start, end] : chunks){
        size_t current_size = end - start;
        vector<char> buffer(current_size);
        
        // Seek to the start of the chunk
        if(lseek(file_dsp, start, SEEK_SET) == (off_t)-1){
            close(file_dsp);
            throw runtime_error("Failed to seek in file " + file_path + ": " + strerror(errno));
        }

        // Read the chunk into buffer
        ssize_t bytes_read = read(file_dsp, buffer.data(), current_size);
        if(bytes_read < 0){
            close(file_dsp);
            throw runtime_error("Error while reading the file " + file_path + " by client to compute hash key: " +strerror(errno));
        }

        // Initialize SHA256 context
        SHA_CTX sha;
        if(!SHA1_Init(&sha)) {
            close(file_dsp);
            throw runtime_error("Failed to initialize SHA256 context.");
        }

        // Update SHA256 with the chunk data
        if(SHA1_Update(&sha, buffer.data(), bytes_read) == 0){
            close(file_dsp);
            throw runtime_error("Failed while updating SHA256 hash key.");
        }

        // Finalize SHA256 hash
        unsigned char hash_key[SHA_DIGEST_LENGTH];
        if(SHA1_Final(hash_key, &sha) == 0){
            close(file_dsp);
            throw runtime_error("Failed while finalizing the SHA256 hash key for the file " + file_path + " by client: " + strerror(errno));
        }

        // Convert binary hash to hexadecimal string and store it
        string hex_hash = change_to_hex(hash_key, SHA_DIGEST_LENGTH);
        chunk_hashes.push_back(hex_hash);
    }
    close(file_dsp);
    return chunk_hashes;
}



void exe_cmnds(int tracker_socket){
    string command;
    while(true){
        getline(cin,command);
        if(command.empty())
            continue;
        if(command=="quit"){
            cout<<"Client node exiting"<<endl;
            close(tracker_socket);
            exit(0);
        }
        
        //send command to tracker
        string cmnd=command+"\n";
        send(tracker_socket,cmnd.c_str(),cmnd.size(),0);
        //cout<<"command sent to tracker"<<endl;
        stringstream ss(cmnd);
        string arg;
        vector<string>cmnd_args;
        while(ss>>arg){
            cmnd_args.push_back(arg);
        }
        if(cmnd_args[0]=="upload_file"){
            //compute the hash value of file and send the meta data  to tracker using send()
            string file_path=cmnd_args[1];
            string grp_id=cmnd_args[2];
            cout<<file_path<<" "<<grp_id<<endl;
            //compute sha key for the file in the above file_path
            vector<string> sha_keys=compute_sha_hash(file_path);
            //get the file meta data details using stat() system call
           // .....
          // cout<<"No.of sha_keys:"<<sha_keys.size()<<endl;
           size_t pos=file_path.find_last_of("/\\");
           string file_name;
           if(pos==string::npos)
                file_name=file_path;
           else
                file_name=file_path.substr(pos+1);
            struct stat file_stat;
            if(stat(file_path.c_str(),&file_stat)==-1)
                throw runtime_error("Error while reading the propertied of file "+file_name+" by client\n");
            size_t file_size=file_stat.st_size;
            //cout<<"At client\n";
           // cout<<file_name<<" "<<file_size<<" "<<sha_key<<endl;
            string upload_info=file_name+" "+to_string(file_size)+" ";
            
            for(int i=0;i<sha_keys.size();i++){
                string temp=to_string(i)+":"+sha_keys[i];
                upload_info+=temp+" ";
            }
            upload_info+="\n";
            send(tracker_socket,upload_info.c_str(),upload_info.size(),0);
          //  cout<<"upload info sent to tracker\n";

            //Recieve response from the tracker
            char tracker_response[1024];
            memset(tracker_response,0,sizeof(tracker_response));
            ssize_t bytes_read=read(tracker_socket,tracker_response,sizeof(tracker_response)-1);
            if(bytes_read<=0){
                cout<<"Tracker closed the connection!"<<endl;
                close(tracker_socket);
                exit(-1);
            }
            //else
            cout<<tracker_response<<endl;
          
        }
        else if(cmnd_args[0]=="download_file"){
            //Recieve response from the tracker with req download info
            char tracker_response[1024];
            memset(tracker_response,0,sizeof(tracker_response));
            ssize_t bytes_read=read(tracker_socket,tracker_response,sizeof(tracker_response)-1);
            if(bytes_read<=0){
                cout<<"Tracker closed the connection!"<<endl;
                close(tracker_socket);
                exit(-1);
            }
            cout<<"GOt info from tracker regarding download"<<endl;
            string download_info(tracker_response,bytes_read);
            cout<<download_info<<endl;
            string info;
            vector<string>download_args;
            stringstream ss(download_info);
            while(ss>>info){
                download_args.push_back(info);
            }
            //cout<<"CP1"<<endl;
            string file_path=download_args[0];
            string seeder_ip=download_args[1];
            int seeder_port=stoi(download_args[2]);
            // string file_sha_key_recv=download_args[3];
            size_t file_size_recv=stoull(download_args[3]);
            //read the sha keys
            vector<pair<int,string>>file_sha_keys_recv;
            int n=download_args.size();
            for(int i=4;i<n;i++){
                string temp=download_args[i];
                int idx=temp.find(":");
                int chunk_num=stoi(temp.substr(0,idx));
                string key=temp.substr(idx+1);
                file_sha_keys_recv.push_back({chunk_num,key});
            }
           // cout<<"CP2"<<endl;

            //connect to this seeder to get the file
            sockaddr_in seeder_addr;
            int seeder_socket=socket(AF_INET,SOCK_STREAM,0);
            if(seeder_socket<0){
            // cout<<"Error in client socket creation"<<endl;
                return;
            }

            int opt = 1;
            if(setsockopt(seeder_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))){
            // perror("setsockopt");
                close(seeder_socket);
                return;
            }
            //intialize the client_addr structure;
            memset(&seeder_addr, 0, sizeof(seeder_addr));
            seeder_addr.sin_family=AF_INET;
            seeder_addr.sin_port=htons(seeder_port);

            //converting IP addr from text to binary
            int pton_result=inet_pton(AF_INET, seeder_ip.c_str(), &seeder_addr.sin_addr);
            if(pton_result<=0){
                //cout<<"Invalid IP address:"<<ip<<endl;
                close(seeder_socket);
                return ;
            }

            //connecting client_socket using system call connect()
           // cout<<"About to connect to seeder"<<endl;
            int connection_result=connect(seeder_socket, (struct sockaddr*)&seeder_addr, sizeof(seeder_addr));
            if(connection_result<0){
                //cout<<"Connection Failed"<<endl;
                close(seeder_socket);
                return;
            }
            //send the download request to seeder
            string download_cmnd="requesting_download "+file_path+"\n";
            send(seeder_socket,download_cmnd.c_str(),download_cmnd.size(),0);

            //receive the file from seeder

            int dest_file_fd=open(cmnd_args[3].c_str(),O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if(dest_file_fd<0){
                cout<<"Error while creating file in destination path"<<endl;
                return;
            }
            ssize_t bytes_written=0;
            char file_buffer[512*1024];
            memset(file_buffer,0,512*1024);//64kb chunks are being read
            ssize_t file_bytes;
            while((file_bytes = read(seeder_socket, file_buffer, sizeof(file_buffer))) > 0){
                ssize_t bytes_written_now = write(dest_file_fd, file_buffer, file_bytes);
                if(bytes_written_now < 0){
                    cerr << "Error writing to destination file." << endl;
                    close(dest_file_fd);
                    close(seeder_socket);
                    // Optionally delete the incomplete file
                    exit(EXIT_FAILURE);
                }
                bytes_written += bytes_written_now;
                // string chunk_cmnd="chunk_download_success\n";
                // send(tracker_socket,chunk_cmnd.c_str(),chunk_cmnd.size(),0);
            }

            //cout<<"CP3"<<endl;
            close(dest_file_fd);
            //validate the sha-key 
           // cout<<"CP4"<<endl;
            vector<string> sha_keys_gen=compute_sha_hash(cmnd_args[3]);
           // cout<<"Sha keys gen size:"<<sha_keys_gen.size()<<endl;
           vector<pair<int,string>>file_sha_keys_gen;
           for(int i=0;i<sha_keys_gen.size();i++){
                file_sha_keys_gen.push_back({i,sha_keys_gen[i]});
           }
            if(validate_sha_keys(file_sha_keys_gen,file_sha_keys_recv)==false || bytes_written!=file_size_recv){
                cout<<"Received corrupted file: sha_keys not matching"<<endl;
                send(seeder_socket,download_cmnd.c_str(),download_cmnd.size(),0);
            }
            // else if(sha_keys_gen.size()!=file_sha_keys_recv.size() || bytes_written!=file_size_recv){
            //     cout<<"Received corrupted file: sha keys not matching"<<endl;
            //     send(seeder_socket,download_cmnd.c_str(),download_cmnd.size(),0);
            // }
            else{
                cout<<"Download completed successfully"<<endl;
                //update the tracker now this file is also available with me
                //dest_file_path-->cmnd_args[3];
                //get destination file name
                string dest_file_path=cmnd_args[3];
                size_t pos=dest_file_path.find_last_of("/\\");
                string dest_file_name;
                if(pos==string::npos)
                    dest_file_name=dest_file_path;
                else
                    dest_file_name=dest_file_path.substr(pos+1);

                string downloaded_file_update="download_success "+dest_file_path+" "+dest_file_name+" "+my_ip+" "+to_string(my_port)+" "+to_string(file_size_recv)+" ";
            //    cout<<"Download msg before appending sha_keys"<<endl;
                for(int i=0;i<file_sha_keys_gen.size();i++){
                    downloaded_file_update+=to_string(i)+":"+file_sha_keys_gen[i].second+" ";
                }
                downloaded_file_update+="\n";
              //  cout<<"Before sending download success from client"<<endl;
                send(tracker_socket,downloaded_file_update.c_str(),downloaded_file_update.size(),0);
               // cout<<"After sending download success to tracker\n";
                 //Recieve response from the tracker
                char tracker_response[1024];
                memset(tracker_response,0,sizeof(tracker_response));
                ssize_t bytes_read=read(tracker_socket,tracker_response,sizeof(tracker_response)-1);
                if(bytes_read<=0){
                    cout<<"Tracker closed the connection!"<<endl;
                    close(tracker_socket);
                    exit(-1);
                }
                //else
                cout<<tracker_response<<endl;
            }
        }
        else{
            //Recieve response from the tracker
            char tracker_response[1024];
            memset(tracker_response,0,sizeof(tracker_response));
            ssize_t bytes_read=read(tracker_socket,tracker_response,sizeof(tracker_response)-1);
            if(bytes_read<=0){
                cout<<"Tracker closed the connection!"<<endl;
                close(tracker_socket);
                exit(-1);
            }
            //else
            cout<<tracker_response<<endl;
        }  
    }
}

bool is_active_tracker(string& ip,int port){
    sockaddr_in temp_addr;
    int temp_tracker=socket(AF_INET,SOCK_STREAM,0);
      if(temp_tracker<0){
       // cout<<"Error in client socket creation"<<endl;
        return false;
    }

    int opt = 1;
    if(setsockopt(temp_tracker, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))){
       // perror("setsockopt");
        close(temp_tracker);
        return false;
    }
    //intialize the client_addr structure;
    memset(&temp_addr, 0, sizeof(temp_addr));
    temp_addr.sin_family=AF_INET;
    temp_addr.sin_port=htons(port);

    //converting IP addr from text to binary
    int pton_result=inet_pton(AF_INET, ip.c_str(), &temp_addr.sin_addr);
    if(pton_result<=0){
        //cout<<"Invalid IP address:"<<ip<<endl;
        close(temp_tracker);
        return false;
    }

    //connecting client_socket using system call connect()
    int connection_result=connect(temp_tracker, (struct sockaddr*)&temp_addr, sizeof(temp_addr));
    if(connection_result<0){
        //cout<<"Connection Failed"<<endl;
        close(temp_tracker);
        return false;
    }
    //test connection with ping msg
    //const char* ping_msg="ping";
   // cout<<"ABout to send my info to tracker\n";
    string client_info=my_ip+" "+to_string(my_port)+"\n";
    string ping_msg="ping "+client_info;
   // cout<<"Ping msg about to sent\n";
    send(temp_tracker,ping_msg.c_str(),ping_msg.size(),0);
    // cout<<"Sent my info to tracker\n ";
    //Recieve response from the tracker
    char tracker_response[1024];
    memset(tracker_response,0,sizeof(tracker_response));
    ssize_t bytes_read=read(temp_tracker,tracker_response,sizeof(tracker_response)-1);
    if(bytes_read<=0){
        cout<<"No tracker response received\n";
       return false;
    }
    //else
    cout<<tracker_response<<"at IP:"<<ip<<" at port:"<<port<<endl;
    tracker_socket=temp_tracker;
    
    return true;
}


void get_all_tracker_info(string& tracker_ip,int& tracker_port,char* tracker_info_file){
    int tracker_file_fd=open(tracker_info_file,O_RDONLY);
    if(tracker_file_fd<0){
        cout<<"Error while opening tracker_info file"<<endl;
        return;
    }
    //reading tracker_info file into a buffer
    char buffer[1024];
    ssize_t bytes_read;
    string file_content = "";
    while((bytes_read = read(tracker_file_fd, buffer, sizeof(buffer)-1)) > 0){
        buffer[bytes_read] = '\0';
        file_content += buffer;
    }
    close(tracker_file_fd);

    //Parsing the content
    vector<pair<string,int>> temp_tracker_info;
    size_t idx=0;
    string ip;
    int port;
    while(idx<file_content.size()){
        size_t eol=file_content.find('\n',idx); //end of the line in file
        if(eol==string::npos) 
            eol=file_content.size();
        string curr_line = file_content.substr(idx,eol-idx);
        idx=eol+1;

        if(curr_line.empty()) 
            continue;

        //processing each line in tracker_info file to get that particular tracker info
        size_t eow=curr_line.find(' '); //end of word -->space encountered
        if(eow==string::npos){
            cerr <<"Invalid line in tracker_info.txt: "<<curr_line<<endl;
            continue;
        }

        ip=curr_line.substr(0,eow);
        port=stoi(curr_line.substr(eow+1));
        temp_tracker_info.push_back({ip,port});
    }
    //finding the active tracker
    bool tracker_found=false;
    for(auto tracker_id:temp_tracker_info){
     //   cout<<"In tracker deatils loop\n";
       // cout<<"tracker ip:"<<tracker_id.first<<"tracker_port:"<<tracker_id.second<<endl;
        if(is_active_tracker(tracker_id.first,tracker_id.second)==true){
            tracker_ip=tracker_id.first;
            tracker_port=tracker_id.second;
            tracker_found=true;
            break;
        }
    }
    if(tracker_found==false){
        cout<<"Error:Failed to connect to an active tracker"<<endl;
        exit(0);
    }
    cout<<"Connected to active tracker at IP "<<tracker_ip<<" with port:"<<tracker_port<<endl;
   
}

//creating socket for the client with the args of cmnd line to make it listen(i.e., it acts as server)
int socket_binding(){
    int temp_socket=socket(AF_INET, SOCK_STREAM, 0);
    if(temp_socket<0){
        cout<<"Error in socket creation"<<endl;
        return -1;
    }
    // Set socket options to reuse address and port
    int opt = 1;
    if(setsockopt(temp_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))){
        perror("setsockopt");
        close(temp_socket);
        return -1;
    }
    //Initialize track_addr structure
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family= AF_INET ;//domain is set to IPV4
    my_addr.sin_port=htons(my_port);//converts the port number from host byte order to network byte order


    //converting IP addr from text to binary
    int pton_result=inet_pton(AF_INET, my_ip.c_str(), &my_addr.sin_addr);
    if(pton_result<=0){
        cout<<"Invalid IP address:"<<my_ip<<endl;
        close(tracker_socket);
        return -1;
    }

    //connecting to tracker using system call bind()
    int connection_result=bind(temp_socket, (struct sockaddr*)&my_addr, sizeof(my_addr));
    if(connection_result<0){
        cout<<"Connection to tracker failed"<<endl;
        close(temp_socket);
        return -1;
    }

    if(listen(temp_socket,10)==-1){
        cout<<"Error while Listening to peers"<<endl;
        return -1;
    }

    return temp_socket;
}
void peer_2_peer_talk(int peer_socket){
    char buffer[1024];
   
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_read=read(peer_socket,buffer,sizeof(buffer)-1);
    if(bytes_read<0){
        cout<<"No request received\n";
        return;
    }
    string cmnd(buffer);
    vector<string>peer_cmnd_args;
    string arg;
    stringstream ss(cmnd);
    while(ss>>arg){
        peer_cmnd_args.push_back(arg);
    }
    if(peer_cmnd_args[0]=="requesting_download"){
        cout<<"Download_request received "<<endl;
        string req_file_path=peer_cmnd_args[1];
        int file_dsp=open(req_file_path.c_str(),O_RDONLY);
        char file_buffer[512*1024];//512 kb chunks are being read
        ssize_t file_bytes;
        while((file_bytes = read(file_dsp, file_buffer, sizeof(file_buffer))) > 0){
            // Correctly construct the string with the exact number of bytes read
            string file_chunk(file_buffer, file_bytes);
            cout << "Sending chunk of size: " << file_bytes << " bytes" << endl;
            if(send(peer_socket, file_chunk.c_str(), file_chunk.size(), 0) < 0){
                cout << "Transfer Failed!" << endl;
                break; // Exit the loop on send failure
            }
        }

        cout << "File sent from seeder" << endl;
        close(file_dsp);        // Close the file descriptor
        close(peer_socket);     // Close the socket to signal end of transfer

    }
    
}
void func_client_listen(){
    vector<thread>peer_clients;
    socklen_t my_addr_len= sizeof(my_addr);
    while(true){
        
        int peer_socket=accept(my_socket, (struct sockaddr*)&my_addr,&my_addr_len);
        if(peer_socket<0){
            cout<<"Error in accepting client connection"<<endl;
            continue;
        }
        cout<<"Client Connection accepted"<<endl;
        peer_clients.emplace_back(peer_2_peer_talk,peer_socket);
    }
}

int main(int argc, char* argv[]){

    if(argc!=3){
        cout<<"Enter arguments as ./client <IP:PORT> tracker_info.txt"<<endl;
        return 1;
    }
    string client_id=argv[1];
    size_t idx=client_id.find(':');
    if(idx==string::npos){
        cout<<"Invalid address format. Use <IP>:<PORT> format"<<endl;
        return 1;
    }
    my_ip=client_id.substr(0,idx);
    my_port=stoi(client_id.substr(idx+1));
    //add functionality::make a listening connection on this client IP and port
    //..
    //1.creats a socket and binds it to the client_ip and port listening socket
    my_socket=socket_binding();
    thread cli_th(func_client_listen);
    cli_th.detach();

    //connect to tracker
    get_all_tracker_info(tracker_ip,tracker_port,argv[2]);//finds and assigns tracker socket
   
    if(tracker_socket==-1){
        cout<<"Error:Connecting to Tracker failed"<<endl;
        return 1;
    }
   
     //execute commands
    exe_cmnds(tracker_socket);
    cli_th.join();
    close(tracker_socket);
    return 0;
}
