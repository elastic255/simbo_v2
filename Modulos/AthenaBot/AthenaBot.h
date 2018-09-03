//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#ifndef INET_APPLICATIONS_SIMBO_MODULOS_ATHENABOT_ATHENABOT_H_
#define INET_APPLICATIONS_SIMBO_MODULOS_ATHENABOT_ATHENABOT_H_

#include "inet/common/INETDefs.h"
#include "inet/applications/httptools/common/HttpMessages_m.h"
#include "inet/applications/simbo/Modulos/GenericBot/GenericBot.h"
#include <random>
#include <limits>
#include <cstring>
#include <regex>
#include <GeoIP.h>
#include <dirent.h>
//#include <experimental/filesystem>
#include <cstdlib>
#include <map>

namespace inet {

namespace simbo {

//
#define HOST_INFECTED 1
#define HOST_NOT_INFECTED 0

// BOT ACTIVITIES
#define MSGKIND_ACTIVITY_BOT_START 4
#define MSGKIND_BOT_START_SESSION  5
#define MSGKIND_BOT_REPEAT_SESSION 6
#define MSGKIND_BOT_RESPONSE_SESSION 7

// BOT COMMANDS EVENT
#define DDOS_ACTIVATE_EVENT      0x10
#define DDOS_DESACTIVATE_EVENT   0x11
#define UNINSTALL_EVENT          0x12
#define DL_EXEC_EVENT            0x13

#define DEFAULT  1000
#define MAX_PATH 260 // WinAPI max length
#define KEY_SIZE 53 // Http build

//Operating Systems
#define WINDOWS_UNKNOWN                 1
#define WINDOWS_2000                    2
#define WINDOWS_XP                      3
#define WINDOWS_2003                    4
#define WINDOWS_VISTA                   5
#define WINDOWS_7                       6
#define WINDOWS_8                       7
#define LINUX                           8

//Max HTTP Packet Stuff
#define MAX_HTTP_PACKET_LENGTH          5000

class INET_API AthenaBot : public GenericBot
{
private:
    /* <------------- Defines Section -------------> */
    enum msg_type {on_exec, repeat, response};
    typedef unsigned int DWORD; // WinAPI 32 bits unsigned integer
    typedef struct _GUID {
      unsigned long  Data1;
      unsigned short Data2;
      unsigned short Data3;
      unsigned char  Data4[8];
    } GUID, UUID;

    typedef std::map<std::string, int> OSMap;
    static OSMap OS_map;

    /* <------------ Variables Section ------------> */
    // OMNeT++ Related
    int pingTime;
    // Event messages - download and execute, uninstall, ddos
    std::map<int, int> commandsMap; // map event msg id to a task id
    cMessage *currentDlExec;
    cMessage *uninstall;
    cMessage *currentDdos;
    cModule *httpModule_dl;
    int dlExecLastMsgId;

    // Host info
    bool isAdmin;
    bool is64Bits;
    bool isLaptop;
    const char *dotNetVersion;
    int numCPUS;

    // Marker and keys
    char cMarker[26];
    char cMarkerBase64[sizeof(cMarker) * 3];
    char cKeyA[KEY_SIZE];
    char cKeyB[KEY_SIZE];

    // Bot global variables

    // Return parameters -- response commands
    char cReturnParameter[5]; // currently, the default response parameter

    //Info
    char            cRegistryKeyAccess[5];
    DWORD           dwOperatingSystem;

    //Botkiller
    DWORD            dwKilledProcesses;
    DWORD            dwFileChanges;
    DWORD            dwRegistryKeyChanges;
    bool             bBotkill;
    //Under here is one-cycle stuff
    bool            bBotkillOnce;
    DWORD           dwKilledProcessesSaved;
    DWORD           dwFileChangesSaved;
    DWORD           dwRegistryKeyChangesSaved;
    bool            bBotkillInitiatedViaCommand;

    //Lock Computer
    bool             bLockComputer;

    //Packet sniff
    bool             bPacketSniffing;

    //Utility Variables
    char            cZoneIdentifierSuffix[25];
    bool            bComputerXpOrUnder;
    char            cFileSaved[MAX_PATH];
    char            cFileSavedDirectory[MAX_PATH];
    char            cThisFile[MAX_PATH];
    unsigned long   ulFileHash;
    char            cFileHash[10];
    char            cBuild[DEFAULT];
    char            cStoreParameter[DEFAULT];
    bool            bStoreParameter;
    bool            bStoreParameter2;
    DWORD           dwStoreParameter;
    char            cMainProcessMutex[DEFAULT];
    char            cBackupProcessMutex[DEFAULT];
    char            cUninstallProcessMutex[DEFAULT];
    char            cUpdateMutex[DEFAULT];
    char            cHostsPath[MAX_PATH];
    char            cReturnNewline[3];
    char            cRegistryKeyToCurrentVersion[MAX_PATH];
    int             nBootType;

    //Ftp related
    char            cFtpUser[DEFAULT];
    char            cFtpPass[DEFAULT];
    char            cFtpHost[DEFAULT];

    //Booleans
    bool            bPersist;
    bool            bSilent;
    bool            bUninstallProgram;
    bool            bNewInstallation;
    bool            bRecoveredProcess;

    //Download, execute, and update related
    char            cDownloadFromLocation[DEFAULT];
    bool            bUpdate;
    bool            bDownloadAbort;
    bool            bExecutionArguments;
    bool            bGlobalOnlyOutputMd5Hash;
    bool            bMd5MustMatch;
    char            szMd5Match[DEFAULT];
    char *          urlDownload;
    char *          fileDownload;

    //Browser related
    char            cBrowsers[5][DEFAULT];

    //Startup Paths
    char            cAllUsersStartupDirectory[MAX_PATH];
    char            cUserStartupDirectory[MAX_PATH];
    char            cAppData[MAX_PATH];
    char            cTempDirectory[MAX_PATH];
    char            cUserProfile[MAX_PATH];
    char            cAllUsersProfile[MAX_PATH];
    char            cProgramFiles[MAX_PATH];

    //Windows Directory
    char            cWindowsDirectory[MAX_PATH];

    //File Search
    unsigned long   ulTotalFiles;
    unsigned long   ulMatchingFiles;
    bool            bOutputFileSearch;
    unsigned int    uiTotalContainingIframeContents;
    bool            bBusyFileSearching;

    //Website visit
    unsigned int    uiSecondsBeforeVisit;
    unsigned int    uiSecondsAfterVisit;
    DWORD           dwSmartViewCommandType;
    unsigned int    uiWebsitesInQueue;

    //Config
    char            cVersion[DEFAULT];
    //char            cServer[DEFAULT];
    const char *cServer;
    char            cBackup[DEFAULT];
    char            cServers[10][MAX_PATH];
    unsigned short  usPort;
    char            cChannel[DEFAULT];
    char            cChannelKey[DEFAULT];
    char            cAuthHost[DEFAULT];
    char            cOwner[DEFAULT];
    char            cServerPass[DEFAULT];

    /*
    //IRC hub management
    unsigned int    nIrcSock;
    char            cSend[MAX_IRC_SND_BUFFER];
    char            cReceive[MAX_IRC_RCV_BUFFER];
    DWORD           dwConnectionReturn;
    char            cNickname[DEFAULT];
    char            *pcParseLine;
    char            *pcPartOfLine;
    char            cIrcMotdOne[DEFAULT];
    char            cIrcMotdTwo[DEFAULT];
    char            cIrcJoinTopic[DEFAULT];
    char            cIrcSetTopic[DEFAULT];
    char            cCommandToChannel[DEFAULT];
    char            cCommandToMe[DEFAULT];
    bool            bAutoRejoinChannel;
    char            cIrcResponseOk[10];
    char            cIrcResponseErr[10];
     */

    //HTTP hub management
    char            cUuid[44];
    int             nCheckInInterval;
    bool            bHttpRestart;
    int             nCurrentTaskId;
    int             nUninstallTaskId;
    char            cHttpHostGlobal[MAX_PATH];
    char            cHttpPathGlobal[MAX_PATH];

    //Flood related
    bool            bDdosBusy;
    DWORD           dwHttpPackets;
    DWORD           dwSockPackets;
    char            cFloodHost[DEFAULT];
    char            cFloodPath[DEFAULT];
    char            cFloodData[DEFAULT];
    unsigned short  usFloodPort;
    unsigned short  usFloodType;
    bool            bBrowserDdosBusy;
    char            urlTarget[MAX_PATH];

    /*
    //Irc War related
    char            cRemoteHost[DEFAULT];
    unsigned short  usRemotePort;
    unsigned short  usRemoteAttemptConnections;
    unsigned short  usRemoteSuccessfulConnections;
    bool            bRemoteIrcBusy;
    SOCKET          sWar[MAX_WAR_CONNECTIONS];
    DWORD           dwOpenSockets;
    char            cRegisterQueryString[DEFAULT];
    DWORD           dwValidatedConnectionsToIrc;
    char            cCurrentWarStatus[100];
    bool            bWarFlood;
    char            cWarFloodTargetParam[DEFAULT];
    bool            bNicknameRegisterTimer;
    bool            bRegisterOnWarIrc;
     */

    //Base 64 characters
    char            cBase64Characters[64];

    //Checksums/CRC/Setup/Config/etc
    unsigned long ulChecksum1;
    unsigned long ulChecksum2;
    unsigned long ulChecksum3;
    unsigned long ulChecksum4;
    unsigned long ulChecksum5;
    unsigned long ulChecksum6;
    unsigned long ulChecksum7;
    unsigned long ulChecksum8;
    unsigned long ulChecksum9;

    //int nPortOffset;

    unsigned short usVersionLength;
    unsigned short usServerLength;
    unsigned short usChannelLength;
    unsigned short usChannelKeyLength;
    unsigned short usAuthHostLength;
    unsigned short usServerPassLength;

    unsigned short usConfigStrlenKey;

    char cIrcCommandPrivmsg[8];
    char cIrcCommandJoin[5];
    char cIrcCommandPart[5];
    char cIrcCommandUser[5];
    char cIrcCommandNick[5];
    char cIrcCommandPass[5];
    char cIrcCommandPong[5];

    bool bConfigSetupCheckpointOne;
    bool bConfigSetupCheckpointTwo;
    bool bConfigSetupCheckpointThree;
    bool bConfigSetupCheckpointFour;
    bool bConfigSetupCheckpointFive;
    bool bConfigSetupCheckpointSix;
    bool bConfigSetupCheckpointEight;
    bool bConfigSetupCheckpointSeven;
    bool bConfigSetupCheckpointNine;
    bool bConfigSetupCheckpointTen;

    int nExpirationDateMedian;

    /* <-------------------------------------------> */

    /* <------------- Methods Section -------------> */
    virtual void initialize(int stage) override;

    void search_reply(std::string p, int line_number, std::string line);

    // OMNeT++ events
    virtual void handleMessage(cMessage *msg) override;
    void handleDataMessage(cMessage *msg);
    void handleSelfMessages(cMessage *msg);
    void handleSelfActivityBotStart();
    void handleSelfBotStartSession();
    void handleSelfBotRepeatSession();
    void handleSelfBotResponseSession(cMessage *msg);
    void handleDlExec(cMessage *msg);
    void handleUninstall();
    void handleActivateDDoS(cMessage *msg);
    void handleDesactivateDDoS();
    void scheduleNextBotEvent(int);

    // Bot functions
    int ConnectToHttp();

    /**
     * WinAPI functions
     */
    void fncUuidCreate(UUID *uuid);
    void fncUuidToString(UUID *, char *);
    void fncRpcStringFree(char *);

    //HOSTENT *fncgethostbyname(char *);
    char *SimpleDynamicXor(char *pcString, DWORD dwKey);

    /**
     * Utilities/ProcessStrings.cpp
     */
    void StripDashes(char *);
    char *StripReturns(char *pcString);

    /*
     * Utilities/ComputerInfo.cpp
     */
    bool IsAdmin();
    bool Is64Bits();
    bool IsLaptop();
    const char *GetVersionMicrosoftDotNetVersion();
    DWORD GetNumCPUs();
    DWORD GetMemoryLoad();

    /**
     * General/DlExecUpdate.cpp
     */
    void DownloadExecutableFile();

    /**
     * Hub/IrcUtilities.cpp
     */
    char *GetOs();

    /*
     * Encryption/Base64_.cpp
     */
    /**
     * characters used for Base64 encoding
     */
    const char *BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    void _base64_encode_triple(unsigned char triple[3], char result[4]);
    int _base64_char_value(char base64char);
    int _base64_decode_triple(char quadruple[4], unsigned char *result);
    size_t base64_decode(const char *source, char *target, size_t targetlen);
    int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);

    /*
     * Hub/HttpUtilities.cpp
     */
    bool SendPanelRequest(char *cHttpHost, char *cHttpPath, unsigned short usHttpPort, char *cHttpData);
    void EncryptSentData(char *cSource, char *cOutputData, char *cOutputEncryptedKey, char *cOutputRawKeyA, char *cOutputRawKeyB);
    int GeneratestrtrKey(char *cOutputA, char *cOutputB);
    void StringToStrongUrlEncodedString(char *cSource, char *cOutput);
    void GenerateMarker(char *cOutput, char *cOutputBase64);
    void DecryptReceivedData(const char *cSource, char *cKeyA, char *cKeyB, char *cOutputData);
    void ParseHttpLine(const char *cMessage);


    /*
     * Utilities/Misc.cpp
     */
    void RunThroughUuidProcedure();
    unsigned long GetRandNum(unsigned long range);
    char *GenRandLCText(); //Generates random lowercase text

    /*
     * Utilities/srandRelated.cpp
     */
    unsigned long GenerateRandomSeed();

    /*
     * Utilities/ProcessStrings.cpp
     */
    void strtr(char *cSource, char *cCharArrayA, char *cCharArrayB);

    /*
     * Protocol/Commands.cpp
     */
    bool HasSpaceCharacter(char *pcScanString); //Checks for any existing space characters in a given string
    char cCharacterPoolOne[99] = "~!@#$%^&*()_+`1234567890-=qwertyuiop[]\\QWERTYUIOP{}|asdfghjkl;\'ASDFGHJKL:\"zxcvbnm,./ZXCVBNM<> ?";
    char cCharacterPoolTwo[99] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890,./<>?;:\'\"[]\\{}|=-+_)(*&^%$#@!~` ";
    char *DecryptCommand(char *pcCommand);
    void ParseCommand(char *pcCommand, int taskId); //Parses an already-processed raw command

    // New commands
    void request_command(char *filename, std::vector<char *> &columns);
    bool isFilePresent(char *filename);
    std::vector<unsigned int> pick_columns_index(std::ifstream &ifs, std::vector<char *> &columns, std::vector<std::string> &result);
    std::string filter_line(std::string &line, std::vector<unsigned int> &columns);
    void ip_conn_req(std::string &orig_h, std::string &orig_p, std::string &proto, std::string &service);
    void ip_conn_resp(std::string &resp_h, std::string &resp_p, std::string &proto, std::string &service);
    void duration_avg(std::string &duration);
    void errors_conn_rate_IP(std::string &orig_h, std::string &conn_state);
    void errors_conn_rate_total(std::string &conn_state);
    void missed_bytes_avg_IP(std::string &orig_h, std::string &missed_bytes);
    void missed_bytes_IP(std::string &orig_h, std::string &missed_bytes);
    void conn_data_IP(std::string &orig_h, std::string &resp_h, std::string &history);
    void conn_data_size_avg_IP(std::string &orig_h, std::string &resp_h, std::string &orig_bytes, std::string &resp_bytes);
    void orig_pkts_avg_IP(std::string &orig_h, std::string &orig_pkts);
    void resp_pkts_avg_IP(std::string &resp_h, std::string &resp_pkts);
    void orig_size_pkts_avg_IP(std::string &orig_h, std::string &orig_ip_bytes);
    void resp_size_pkts_avg_IP(std::string &resp_h, std::string &resp_ip_bytes);
    void tunneled_conn(std::string &tunnel_parents);
    void orig_geoIP(const std::string orig_h);
    void resp_geoIP(const std::string resp_h);
    void send_result(char *file, std::vector<std::string> &result);
    void findIndexes(char *filename, std::map<std::string, int> &index, std::string &line);


    void http_IP_list(std::string &orig_h, std::string &resp_h);
    void http_src_ports(std::string &orig_p);
    void http_dst_ports(std::string &resp_p);
    void http_rank_ips_req(std::string &resp_h);
    void http_req_body_len_avg(std::string &req_body_len);
    void http_resp_body_len_avg(std::string &resp_body_len);
    void http_method_list(std::string &method);
    void http_req_host_size_avg(std::string &host);
    void http_req_uri_size_avg(std::string &uri);
    void http_req_referrer_size_avg(std::string &referrer);
    void http_req_user_agent_size_avg(std::string &user_agent);
    void http_sensitive_user(std::string &username);
    void http_sensitive_password(std::string &password);

    void dns_IP_list(std::string &orig_h, std::string &resp_h);
    void dns_proto(std::string &proto);
    void dns_is_IP_bot_server(std::string &resp_h);
    void dns_is_bot_recursive(std::string &resp_h, std::string &RA, std::string &RD);
    bool isLocalIP(std::string &ip);
    void dns_is_resp_local_port(std::string &resp_p);
    void dns_is_resp_local_mdns_port(std::string &resp_p);
    void dns_is_resp_local_llmnr_port(std::string &resp_p);
    void dns_is_resp_local_netb_port(std::string &resp_p);
    void dns_is_there_recursive_net(std::string &resp_h, std::string &RA, std::string &RD);
    void dns_is_allow_extern_req(std::string &orig_h, std::string &resp_h, std::string &RA, std::string &RD);
    void dns_is_bot_auth_server(std::string &resp_h, std::string &RA, std::string &RD);
    void dns_is_auth_server_net(std::string &resp_h, std::string &RA, std::string &RD);
    std::string dns_boolOutput(bool value);

private:
    std::set<std::string> dns_IPs;
    bool dnsProto = false;
    bool dns_isServer = false;
    bool dns_isRecursive = false;
    bool dns_isLocal = false;
    bool dns_isMDNS = false;
    bool dns_isLLMNR = false;
    bool dns_isNETB = false;
    bool dns_isRecursiveNet = false;
    bool dns_allowExtern = false;
    bool dns_isAuth = false;
    bool dns_isAuthNet = false;

    std::string myIP;
    std::set<std::string> IP_list;
    std::set<std::string> IP_src_ports;
    std::set<std::string> IP_dst_ports;
    std::map<std::string, int> IP_rank_req;
    int http_events = 0;
    double http_req_body = 0;
    double http_resp_body = 0;
    std::set<std::string> http_methods;
    double http_host = 0;
    double http_uri = 0;
    double http_referrer = 0;
    double http_user_agent = 0;
    std::set<std::string> http_usernames;
    std::set<std::string> http_passwords;

public:
    GeoIP *gi = GeoIP_open("/usr/share/GeoIP/GeoIP.dat", GEOIP_STANDARD | GEOIP_CHECK_CACHE);
    class IP_data
    {
    private:
        std::set<std::string> ports;
        std::set<std::string> protocols;
        std::set<std::string> services;
    public:
        IP_data() {};
        void insertPort(std::string port) { ports.insert(port); }
        void insertProtocol(std::string protocol) { protocols.insert(protocol); }
        void insertService(std::string service) { services.insert(service); }
        std::string getPorts() {
            std::ostringstream ss;
            std::set<std::string>::iterator it = ports.begin();
            if (it == ports.end()) return "-";
            ss << *it;
            for (it++; it != ports.end(); ++it)
                ss << "," << *it;
            return ss.str();
        }
        std::string getProtocols() {
            std::ostringstream ss;
            std::set<std::string>::iterator it = protocols.begin();
            if (it == protocols.end()) return "-";
            ss << *it;
            for (it++; it != protocols.end(); ++it)
                ss << "," << *it;
            return ss.str();
        }
        std::string getServices() {
            std::ostringstream ss;
            std::set<std::string>::iterator it = services.begin();
            if (it == services.end()) return "-";
            ss << *it;
            for (it++; it != services.end(); ++it)
                ss << "," << *it;
            return ss.str();
        }
    };

    class Missed_bytes
    {
    private:
        int missed_bytes;
        int events;
        int events_missed;
    public:
        Missed_bytes() { missed_bytes = 0; events = 0; events_missed = 0; }
        void addMissedBytes(int missed_byte) { missed_bytes += missed_byte; events++; }
        void incrementMissedEvents() { events_missed++; }
        double avg() { return events == 0 ? 0 : (double) missed_bytes/events; }
        int getTotalMissedEvents() { return events_missed; }
    };

    class Bytes_sum
    {
    private:
        int bytes;
        int events;
    public:
        Bytes_sum() { bytes = 0; events = 0; }
        void addBytes(int byte) { bytes += byte; events++; }
        double avg() { return events == 0 ? 0 : (double) bytes/events; }
    };

    class Pkts_sum
    {
    private:
        int pkts;
        int events;
    public:
        Pkts_sum() { pkts = 0; events = 0; }
        void addPkts(int pkt) { pkts += pkt; events++; }
        double avg() { return events == 0 ? 0 : (double) pkts/events; }
    };

private:
    std::map<std::string, bool> files;
    std::string files_path;
    std::map<std::string, IP_data> ip_conn_req_;
    std::map<std::string, IP_data> ip_conn_resp_;
    std::map<std::string, Missed_bytes> missed_bytes_;
    std::map<std::string, int> conn_data_;
    std::map<std::string, Bytes_sum> conn_data_size;
    std::map<std::string, Pkts_sum> orig_pkts_;
    std::map<std::string, Pkts_sum> resp_pkts_;
    std::map<std::string, Bytes_sum> orig_size_pkts;
    std::map<std::string, Bytes_sum> resp_size_pkts;
    std::map<std::string, std::string> orig_geo;
    std::map<std::string, std::string> resp_geo;
    bool hasTunneled = false;
    const char *delimiters;
    unsigned int count_event = 0;
    std::map<std::string, int> errors;
    int errors_total = 0;
    unsigned int total_duration = 0;

/********* conn.log **************/
private:
    // bot_info
    int bot_num_conn = 0;
    std::set<int> bot_orig_ports;
    std::set<int> bot_resp_ports;
    std::set<int> bot_protocols;
    std::set<int> bot_services;
    double bot_tx_pkts_rcv = 0.0;
    double bot_tx_pkts_sent = 0.0;
    double bot_tx_pkts_total = 0.0;
    double bot_tx_bytes_rcv = 0.0;
    double bot_tx_bytes_sent = 0.0;
    double bot_tx_bytes_total = 0.0;
    double bot_tx_errors = 0.0;
    int bot_errors_total = 0.0;
    bool bot_tunneled = false;
    bool bot_proxy = false;
    bool bot_http = false;
    bool bot_https = false;
    bool bot_dns = false;
    bool bot_smtp = false;
    bool bot_mysql = false;
    bool bot_ftp = false;
    bool bot_telnet = false;
    bool bot_ssh = false;
    bool bot_snmp = false;
    bool bot_irc = false;

    // net_info
    int net_num_conn = 0;
    std::set<int> net_orig_ports;
    std::set<int> net_resp_ports;
    std::set<std::string> net_devices;
    std::set<int> net_protocols;
    std::set<int> net_services;
    double net_tx_pkts = 0.0;
    double net_tx_errors = 0.0;
    int net_errors_total = 0;
    bool net_tunneled = false;
    bool net_proxy = false;
    bool net_http = false;
    bool net_https = false;
    bool net_dns = false;
    bool net_smtp = false;
    bool net_mysql = false;
    bool net_ftp = false;
    bool net_telnet = false;
    bool net_ssh = false;
    bool net_snmp = false;
    bool net_irc = false;

public:
    // bot_info
    void bot_orig_ports_add(std::string &orig_h, std::string &port);
    void bot_resp_ports_add(std::string &resp_h, std::string &port);
    void bot_protocols_add(std::string &proto);
    void bot_services_add(std::string &service);
    void bot_pkts_rcv_add(std::string &pkts);
    void bot_pkts_sent_add(std::string &pkts);
    void bot_bytes_rcv_add(std::string &bytes);
    void bot_bytes_sent_add(std::string &bytes);
    void bot_tx_errors_add(std::string &conn_state);
    void bot_is_tunneled(std::string &tunnel_parents);
    void bot_is_proxy(std::string &port);

    // net_info
    void net_orig_ports_add(std::string &port);
    void net_resp_ports_add(std::string &port);
    void net_devices_add(std::string &orig_h);
    void net_protocols_add(std::string &protocol);
    void net_services_add(std::string &service);
    void net_tx_pkts_add(std::string &orig_pkts, std::string &resp_pkts);
    void net_tx_errors_add(std::string &conn_state);
    void net_is_tunneled(std::string &tunnel_parents);
/*******************************/

    std::string bool_output(bool value);
public:
    AthenaBot();
    virtual ~AthenaBot();
};

} /* namespace simbo */

} /* namespace inet */

#endif /* INET_APPLICATIONS_SIMBO_MODULOS_ATHENABOT_ATHENABOT_H_ */
