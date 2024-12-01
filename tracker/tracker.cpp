#include <iostream>
#include <string.h> //for memset and substr()
#include <netinet/in.h> //for sockaddr_in
#include <arpa/inet.h> //functions for IP addrr manipulation: inet_pton
#include <sys/socket.h>//for socket(),connect()
#include <unistd.h>//for close()
#include <sstream> // for stringstream()
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <mutex>
#include <vector>
#include <thread>
#include <cstring>
#include <fcntl.h>
#include <cstdlib>
#include <openssl/sha.h>
#include <iomanip>
#include <endian.h>
#include <stdexcept> 
using namespace std;
//To store Tracker details
string curr_tracker_ip;
int curr_tracker_port;
vector<pair<string,int>> trackerinfo;
thread_local string curr_user="";
struct files_info
{
    string file_name;
    string file_path;
    string file_seeder;//user _id of the user who uploaded file
    string file_seeder_ip;
    int file_seeder_port;
    vector<pair<int,string>> file_sha_keys;
    string file_size;
};
// to track client activities
unordered_map<string,string> log_creds; //userid-->pwd
unordered_map<string,bool> isloggedin;  //userid-->isloggedin?
unordered_map<string,string> grp_owners; //grpid-->ownerofgrp
unordered_map<string,unordered_set<string>> user_grps;//user_id-->groups in which he is a member
unordered_map<string,unordered_set<string>> grp_mems; //grpid-->list of members
unordered_map<string,unordered_set<string>> grp_pend_reqs; //grpid--> list of req pending
unordered_map<string,pair<string,int>>user_details; //user_id-->{user_ip,user_port}
unordered_map<string,vector<files_info>>grp_files;//grp_id-->list of files available in the grp
unordered_map<string,vector<files_info>> user_files;//user_id-->(list of file records available with user)
//we should also store which user has which chunks ready with him

//for concurrency of peers
mutex mt_log_creds;
mutex mt_logged_in;
mutex mt_grp_owners;
mutex mt_grp_mems;
mutex mt_grp_pend_reqs;
void func_create_user(int client_socket, string& user_id, string& pwd,string &send_response){
    lock_guard<mutex> lock(mt_log_creds);
    if(log_creds.find(user_id) != log_creds.end()){
        send_response="User already exists.\n";
        return;
    }
    else{
        log_creds[user_id]=pwd;
        send_response="User created successfully.\n";
        cout<<"User created: "<<user_id<<endl;
        return;
    }
}
void func_login_user(int client_socket, string& user_id, string& pwd,string user_ip, int user_port,string &send_response){
    lock_guard<mutex>lock1(mt_log_creds);
    if(log_creds.find(user_id)==log_creds.end()){
        send_response="User does not exist\n";
    }
    else{
        if(log_creds[user_id]!=pwd){
            send_response="Incorrect password\n";
        }
        else{
            lock_guard<mutex>lock2(mt_logged_in);
            if(isloggedin[user_id]==true){
                send_response="User already logged in\n";
            }
            else{
                isloggedin[user_id]=true;
                //storing user_id with their respective ip and port
                user_details[user_id]={user_ip,user_port};
                curr_user=user_id;
                send_response="Login successful\n";
                cout<<"User logged in: "<<user_id<<endl;
            }
        }
    }
}
void func_create_group(int client_socket, string& grp_id,string &send_response){
    if(curr_user.empty() || isloggedin[curr_user]==false){
        send_response="Please login before to create a group\n";
        return;
    }
    lock_guard<mutex>lock(mt_grp_owners);
    if(grp_owners.find(grp_id)!=grp_owners.end()){
        send_response="Group already exists\n";
    }
    else{
        grp_owners[grp_id]=curr_user;
        lock_guard<mutex> lock2(mt_grp_mems);
        grp_mems[grp_id].insert(curr_user);
        user_grps[curr_user].insert(grp_id);
        send_response="Group created successfully\n";
        cout<<"Group created: "<<grp_id<<" by "<<curr_user<<endl;
    }
}
void func_join_group(int client_socket, string& grp_id,string &send_response){
    if(curr_user.empty() || isloggedin[curr_user]==false){
        send_response="Please login before to create a group\n";
        return;
    }
    lock_guard<mutex>lock1(mt_grp_owners);
    if(grp_owners.find(grp_id)==grp_owners.end()){
        send_response="Group does not exist\n";
    }
    else{
        lock_guard<mutex>lock2(mt_grp_mems);
        if(grp_mems[grp_id].find(curr_user)!=grp_mems[grp_id].end()){ //if the curr_user is already a grp member
            send_response="Already a member of the group\n";
        }
        else{
            lock_guard<mutex>lock3(mt_grp_pend_reqs);
            grp_pend_reqs[grp_id].insert(curr_user); //curr_user is waiting to join this grp_id
            send_response="Join request sent\n";
            cout<<"User "<<curr_user<<" requested to join group "<<grp_id<<endl;
        }
    }
}
void func_leave_group(int client_socket, string& grp_id,string &send_response){
    if(curr_user.empty() || isloggedin[curr_user]==false){
       send_response="Please login before to create a group\n";
        return;
    }
    lock_guard<mutex>lock1(mt_grp_mems);
    if(grp_mems.find(grp_id)==grp_mems.end()){//if there is no group existing with this group id
        send_response="Group does not exist\n";
    }
    else{
        if(grp_mems[grp_id].find(curr_user)==grp_mems[grp_id].end()){//if curr_user not present in grp_mems list
            send_response="Not a member of the group\n";
        }
        else{
            grp_mems[grp_id].erase(curr_user);
            user_grps[curr_user].erase(grp_id);
            send_response="Left the group successfully\n";
            if(grp_owners[grp_id]==curr_user){//i.e.,owner itself left the group..make other member as owner
                if(grp_mems[grp_id].size()==0){//empty group
                    cout<<"Group "<<grp_id<<" is now empty..So deleting group "<<grp_id<<endl;
                    grp_owners.erase(grp_id);
                    grp_mems.erase(grp_id);
                }
                else if(grp_mems[grp_id].size()>0){//new owner found
                    string new_owner=*grp_mems[grp_id].begin();
                    cout<<"Owner left the group! new group owner for "<<grp_id<<" is "<<new_owner<<endl;
                    grp_owners[grp_id]=new_owner;
                }
            }
            
            cout<<"User "<<curr_user<<" left group "<<grp_id<<endl;
        }
    }
}

void func_list_req(int client_socket, string& grp_id,string &send_response){
    if(curr_user.empty() || isloggedin[curr_user]==false){
        send_response="Please login before to create a group\n";
        return;
    }
    string owner=curr_user; // Placeholder; in real scenario, verify admin
    lock_guard<mutex>lock1(mt_grp_owners);
    if(grp_owners.find(grp_id)==grp_owners.end()){
        send_response="Group does not exist\n";
    }
    else{
        if(grp_owners[grp_id]!=owner){
            send_response="Only group owner can view pending requests\n";
        }
        else{
            lock_guard<mutex>lock2(mt_grp_pend_reqs);
            if(grp_pend_reqs[grp_id].empty()){
                send_response="No pending requests\n";
            }
            else{
                send_response="Pending Requests:\n";
                for(auto &req:grp_pend_reqs[grp_id]){
                    send_response+=(req+"\n");
                }
            }
        }
    }
}
void func_accept_req(int client_socket, string& grp_id, string& user_id,string &send_response){
     if(curr_user.empty() || isloggedin[curr_user]==false){
        send_response="Please login before to create a group\n";
        return;
    }
    lock_guard<mutex>lock1(mt_grp_owners);
    if(grp_owners.find(grp_id)==grp_owners.end()){
        send_response="Group does not exist\n";
    }
    else{
        if(grp_owners[grp_id]!=curr_user){
            send_response="Only group owner can accept requests\n";
        }
        else{
            lock_guard<mutex>lock2(mt_grp_pend_reqs);
            if(grp_pend_reqs[grp_id].find(user_id)==grp_pend_reqs[grp_id].end()){
                send_response="No such pending request\n";
            }
            else{
                grp_pend_reqs[grp_id].erase(user_id);
                lock_guard<mutex>lock3(mt_grp_mems);
                grp_mems[grp_id].insert(user_id);
                user_grps[user_id].insert(grp_id);
                send_response="User added to the group\n";
                cout<<"User "<<user_id<<" added to group "<<grp_id<<" by "<<curr_user<<endl;
            }
        }
    }
}
void func_list_all_grps(int client_socket,string &send_response){
    if(curr_user.empty() || isloggedin[curr_user]==false){
        send_response="Please login before to create a group\n";
        return;
    }
    lock_guard<mutex>lock(mt_grp_owners);
    if(grp_owners.empty()){
        send_response="No groups available.\n";
    }
    else{
        send_response="Groups:\n";
        for(auto &grp:grp_owners){
            send_response+=(grp.first+"\n");
        }
    }
}
void func_logout(int client_socket,string &send_response){
    if(!curr_user.empty()){
        lock_guard<std::mutex> lock(mt_logged_in);
        isloggedin[curr_user]=false;
        user_details.erase(curr_user);

        send_response="User logged out\n";
    }
    //close(client_socket);
    return;
}
void func_upload(int client_socket, string& file_path, string& grp_id,string &send_response){
    if(curr_user.empty() || isloggedin[curr_user]==false){
        send_response="Please login before to upload a file\n";
        return;
    }
    //check if the user is present in the grp with grp_id or not
    if(!(grp_mems[grp_id].count(curr_user))){ //if the current user is not present in the grp_id, they cannont upload the file in that grp
        cout<<"Error: Client "<<curr_user<<" is not part of the grp "<<grp_id<<". Cannont upload the file"<<endl;
        send_response="Upload failed as you are not memner of the group\n";
        return;
    }
    char buffer[2048];
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer)-1);
    if(bytes_read<0){
        throw runtime_error("Error while retrieving the file info of sent by client\n");
    }
    string arg;
    vector<string>upload_args;
    string upload_details(buffer,bytes_read);
    stringstream ss(upload_details);
    ss>>arg;
    string file_name=arg;
    ss>>arg;
    string file_size=arg;
    vector<pair<int,string>>sha_keys_recv;
    while(ss>>arg){
        string key_comb=arg;
        int idx=key_comb.find(':');
        int chunk_num=stoi(key_comb.substr(0,idx));
        string key=key_comb.substr(idx+1);
        sha_keys_recv.push_back({chunk_num,key});
    }

    struct files_info file_record;
    file_record.file_name=file_name;
    file_record.file_seeder=curr_user;
    file_record.file_path=file_path;
    file_record.file_seeder_ip=user_details[curr_user].first;
    file_record.file_seeder_port=user_details[curr_user].second;
    file_record.file_sha_keys=sha_keys_recv;
    file_record.file_size=file_size; 
    grp_files[grp_id].push_back(file_record);
    user_files[curr_user].push_back(file_record);
    cout<<"File "+file_name+" uploaded successfully by "+curr_user+"\n";
    send_response="File uploaded\n";

}
void func_download(int client_socket, string& grp_id, string& file_name, string&dest_path,string &send_response){
    if(!(grp_mems[grp_id].count(curr_user))){
        send_response="You are not part of the grp "+grp_id+" to download the file\n";
        return;
    }
    int flag=0;
    //check whteher this files are present in the grp
    for(auto& file_record:grp_files[grp_id]){
        if(file_record.file_name==file_name){
            //send the file meta details and seeder info to the client that is requesting for download
            send_response=file_record.file_path+" "+file_record.file_seeder_ip+" "+to_string(file_record.file_seeder_port)+" "+file_record.file_size+" ";
            //still need to send shakeys
            vector<pair<int,string>>sha_keys=file_record.file_sha_keys;
            for(int i=0;i<sha_keys.size();i++){
                send_response+=to_string(sha_keys[i].first)+":"+sha_keys[i].second+" ";
            }
            send_response+="\n";
            cout<<"File details of "<<file_name<<" are sent to client "<<curr_user<<endl;
            cout<<send_response<<endl;
            flag=1;
            break;
        }
    }
    if(!flag){
        send_response="No such file in the grp "+grp_id+"\n";
        return;
    }
}
void func_list_grp_files(int client_socket,string& grp_id,string &send_response){
    if(grp_owners.find(grp_id)==grp_owners.end()){
        //i.e., group doesn't exist
        send_response="No grp "+grp_id+" exists";
        return;
    }
    send_response="List of files in grp "+grp_id+":\n";
    for(auto&record:grp_files[grp_id]){ 
        send_response+=record.file_name+"\n";
    }
}
void manage_client_cmnds(int client_socket){
    string curr_user_ip;
    int curr_user_port;
    string send_response="";
    char buffer[1024];
    while(true){
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer)-1);
        if(bytes_read<=0){
            // Connection closed or error
          //  cout<<"Closing connection on error"<<endl;
            if(!(curr_user.empty())){
                lock_guard<std::mutex> lock(mt_logged_in);
                isloggedin[curr_user]=false;
                cout<<"User logged out"<<endl;
            }
            close(client_socket);
            return;
        }
        string command(buffer); //entire command
        //remove the extra line
        if(!command.empty() && command.back()=='\n')
            command.pop_back();

        stringstream ss(command); //tokenizing
        string cmnd;
        if(command.empty()){
            send_response="Try again\n";
            continue;
        }
        vector<string>cmnd_args;
        while(ss>>cmnd){
            cmnd_args.push_back(cmnd);
        }
        if(cmnd_args[0]=="create_user")
        {
            if(cmnd_args.size()!=3){
                send_response="Invalid number of arguments\n";
            }
            else{
                string user_id,pwd;
                user_id=cmnd_args[1];
                pwd=cmnd_args[2];
                func_create_user(client_socket, user_id, pwd,send_response);
            }
            
        }
        else if(cmnd_args[0]=="login"){
            if(cmnd_args.size()!=3){
                send_response="Invalid number of arguments\n";
            }
            else{
                string user_id,pwd;
                user_id=cmnd_args[1];
                pwd=cmnd_args[2];
                func_login_user(client_socket,user_id,pwd,curr_user_ip,curr_user_port,send_response);
            } 
        }
        else if(cmnd_args[0]=="create_group"){
            if(cmnd_args.size()!=2){
                send_response="Invalid number of arguments\n";
            }
            else{
                string grp_id;
                grp_id=cmnd_args[1];
                func_create_group(client_socket,grp_id,send_response);
            }
        }
        else if(cmnd_args[0]=="join_group"){
            if(cmnd_args.size()!=2){
                send_response="Invalid number of arguments\n";
            }
            else{
                string grp_id;
                grp_id=cmnd_args[1];
                func_join_group(client_socket,grp_id,send_response);
            }
        }
        else if(cmnd_args[0]=="leave_group"){
            if(cmnd_args.size()!=2){
                send_response="Invalid number of arguments\n";
            }
            else{
                string grp_id;
                grp_id=cmnd_args[1];
                func_leave_group(client_socket,grp_id,send_response);
            }
        }
        else if(cmnd_args[0]=="list_requests"){//Pending Join requests
            if(cmnd_args.size()!=2){
                send_response="Invalid number of arguments\n";
            }
            else{
                string grp_id;
                grp_id=cmnd_args[1];
                func_list_req(client_socket,grp_id,send_response);
            }    
        }
        else if(cmnd_args[0]=="accept_request"){ //Accepts Group Join Request
            if(cmnd_args.size()!=3){
                send_response="Invalid number of arguments\n";
            }
            else{
                string grp_id,user_id;
                grp_id=cmnd_args[1];
                user_id=cmnd_args[2];
                func_accept_req(client_socket,grp_id,user_id,send_response);
            }   
        }
        else if(cmnd_args[0]=="list_groups"){//Lists all groups in the network
            if(cmnd_args.size()!=1){
                send_response="Invalid number of arguments\n";
            }
            else{
                func_list_all_grps(client_socket,send_response);
            }     
        }
        else if(cmnd_args[0]=="upload_file"){//to upload a file
            if(cmnd_args.size()!=3){
                send_response="Invalid number of arguments\n";
            }
            else{
                func_upload(client_socket,cmnd_args[1],cmnd_args[2],send_response);
            }

        }
        else if(cmnd_args[0]=="download_file"){
            if(cmnd_args.size()!=4){
                send_response="Invalid number of arguments\n";
            }
            else{
                func_download(client_socket,cmnd_args[1],cmnd_args[2],cmnd_args[3],send_response);
            }
        }
        else if(cmnd_args[0]=="chunk_download_success"){

        }
        else if(cmnd_args[0]=="download_success"){
            //updating the downloaded file from the client to database
            struct files_info file_record;
            file_record.file_path=cmnd_args[1];
            file_record.file_seeder=curr_user;
            file_record.file_name=cmnd_args[2];
            file_record.file_seeder_ip=cmnd_args[3];
            file_record.file_seeder_port=stoi(cmnd_args[4]);
            //file_record.file_sha_key=cmnd_args[5];
            file_record.file_size=cmnd_args[5];
          //  cout<<"In download success func"<<endl;
            vector<pair<int,string>>sha_keys;
            for(int i=6;i<cmnd_args.size();i++){
                string temp=cmnd_args[i];
                int idx=temp.find(":");
                int chunk_num=stoi(temp.substr(0,idx));
                string key=temp.substr(idx+1);
                sha_keys.push_back({chunk_num,key});
            }
            file_record.file_sha_keys=sha_keys;
          //  cout<<"After download, no.of sha_keys:"<<sha_keys.size()<<endl;
        
            //updating all the grps in which this curr user is a member with this file info, as he can share it in those grps also
            unordered_set<string> curr_user_grp_ids=user_grps[curr_user];
            for(auto&x: curr_user_grp_ids){
                grp_files[x].push_back(file_record);
            }
            //updating that this curr user is now having this file
            user_files[curr_user].push_back(file_record);
            cout<<"Updated downloaded File info of "+cmnd_args[2]+" successfully, downloaded by "+curr_user+"\n";
            send_response="successfully updated downloaded file , by "+curr_user+"\n";
        }
        else if(cmnd_args[0]=="logout"){
            if(cmnd_args.size()!=1){
                send_response="Invalid number of arguments\n";
            }
            else{

                func_logout(client_socket,send_response);
                cout<<"User "<<curr_user<<" logged out"<<endl;
            } 
        }
        else if(cmnd_args[0]=="list_files"){
            if(cmnd_args.size()!=2){
                send_response="Invalid number of arguments\n";
            }
            else{
                func_list_grp_files(client_socket,cmnd_args[1],send_response);
            }
        }
        else if(cmnd_args[0]=="ping"){
            //update user_deatils of ip and port;
            curr_user_ip=cmnd_args[1];
            curr_user_port=stoi(cmnd_args[2]);
            send_response="Active tracker found ";
        }
        else if(cmnd_args[0]=="help"){
            send_response="Available Commands:\n";
            send_response+="create_user <user_id> <passwd>\n";
            send_response+="login <user_id> <passwd>\n";
            send_response+="create_group <group_id>\n";
            send_response+="join_group <group_id>\n";
            send_response+="leave_group <group_id>\n";
            send_response+="list_requests <group_id>\n";
            send_response+="accept_request <group_id> <user_id>\n";
            send_response+="list_groups\n";
            send_response+="upload_file <file_path> <group_id>\n";
            send_response+="download_file <group_id> <file_name> <destination_path>";
            send_response+="list_files <group_id>";
            send_response+="logout\n";
        }
        else{
            send_response="Unknown command(Type help to find available commands)\n";
        }
          // Send response to client
        write(client_socket, send_response.c_str(),send_response.size());
        send_response="";
    }
}
int connect_tracker(struct sockaddr_in &track_addr){
    int tracker_socket;
    //struct sockaddr_in track_addr;
    tracker_socket=socket(AF_INET, SOCK_STREAM, 0);
    if(tracker_socket<0){
        cout<<"Error in socket creation"<<endl;
        return -1;
    }
    // Set socket options to reuse address and port
    int opt = 1;
    if(setsockopt(tracker_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))){
        perror("setsockopt");
        close(tracker_socket);
        return -1;
    }
    //Initialize track_addr structure
    memset(&track_addr, 0, sizeof(track_addr));
    track_addr.sin_family= AF_INET ;//domain is set to IPV4
    track_addr.sin_port=htons(curr_tracker_port);//converts the port number from host byte order to network byte order
    //converting IP addr from text to binary
    int pton_result=inet_pton(AF_INET, curr_tracker_ip.c_str(), &track_addr.sin_addr);
    if(pton_result<=0){
        cout<<"Invalid IP address:"<<curr_tracker_ip<<endl;
        close(tracker_socket);
        return-1;
    }
    //connecting to tracker using system call bind()
    int connection_result=bind(tracker_socket, (struct sockaddr*)&track_addr, sizeof(track_addr));
    if(connection_result<0){
        cout<<"Connection to tracker failed"<<endl;
        close(tracker_socket);
        return -1;
    }

    return tracker_socket; //this is returned if all the stages like creation , initialization, conversion and connection are done.
}
bool evaluate_args(int argc, char *argv[], int &tracker_num){
    //agrv[0]->./tracker (prgm name)
    //argv[1]-> tracker file name
    //argv[2]-> tracker number
    if(argc!=3){
        cout<<"Enter arguments as ./tracker tracker_info.txt tracker_no" << endl;
        return 1;
    }

    tracker_num= atoi(argv[2]); 
    if(tracker_num <= 0){
        cout << "Invalid tracker number.\n";
        return false;
    }
    char* tracker_file_name=argv[1];
    int tracker_file_fd=open(tracker_file_name,O_RDONLY);
    if(tracker_file_fd<0){
        cout<<"Error while opening tracker_info file"<<endl;
        return false;
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

        temp_tracker_info.push_back({ip, port});//vector of all trackers info
    }

    if(tracker_num>temp_tracker_info.size()){
        cout<<"Tracker number is greater than number of trackers present in Info file"<<endl;
        return false;
    }
    //if successful in finding tracker assign it 
    trackerinfo=temp_tracker_info;
    curr_tracker_ip=trackerinfo[tracker_num-1].first;
    curr_tracker_port=trackerinfo[tracker_num-1].second;
    return true;
}
void func_quit(int tracker_socket){
    string cmnd;
    while(true){
        cin>>cmnd;
        if(cmnd=="quit"){
            cout<<"Shutting down tracker"<<endl;
            exit(0);
        }
    }
}
int main(int argc,char* argv[]){

    int tracker_num;
    if(evaluate_args(argc,argv,tracker_num)==false){
        return -1;
    }
    cout<<"Using tracker at port :"<<curr_tracker_port<<"with IP:"<<curr_tracker_ip<<endl;

    struct sockaddr_in track_addr;
    //create tracker socket
    int tracker_socket=connect_tracker(track_addr); //creacting tracker socket
    cout<<"Tracker socket connected successfully"<<endl;
    if(listen(tracker_socket,10)<0){ 
        cout<<"Listening failed by tracker"<<endl;
        close(tracker_socket);
        return 1; 
    } 
    cout<<"Tracker Listening for connections..."<<endl;
    //handling quit 
    thread quit_th(func_quit,tracker_socket);
    quit_th.detach(); //it should run independently
    //to respond to clients concurrently
    vector<thread>client_threads;
    while(true){//accepting connections from clients
        socklen_t track_addr_len= sizeof(track_addr);
        //accept() function is used to accept an incoming client connection.
        //accept() function creates a new socket descriptor (client_socket) for each connected client, 
        //which will be used to communicate with that particular client.
        int client_socket=accept(tracker_socket, (struct sockaddr*)&track_addr,&track_addr_len);
        if(client_socket<0){
            cout<<"Error in accepting client connection"<<endl;
            continue;
        }
        cout<<"Client Connection accepted"<<endl;

        //create a new thread for each client connection
        //This thread will execute the function manage_client_cmnds, passing client_socket as the argument.

        client_threads.emplace_back(manage_client_cmnds,client_socket);
    }
    cout<<"Tracker exiting"<<endl;
    close(tracker_socket);
    return 0;
}
