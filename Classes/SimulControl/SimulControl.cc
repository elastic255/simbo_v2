/*
 * SimulControl.cpp
 *
 *  Created on: Apr 19, 2018
 *      Author: fabio
 */

#include "../SimulControl/SimulControl.h"

namespace inet {

namespace simbo {

SimulControl::SimulControl() {
    // TODO Auto-generated constructor stub

}

SimulControl::~SimulControl() {
    // TODO Auto-generated destructor stub
}

bool SimulControl::read_command(char *command)
{
    bool ret = true;
    char *token = strtok(command, " ");
    //EV_INFO << "Received a command" << std::endl;
    if (strcmp(token, "infect") == 0) {
        char *host_name = strtok(NULL, " ");
        infect_command(host_name);
        //EV_INFO << "infect command received" << std::endl;
    }
    else {
        //EV_INFO << "Something went wrong!" << std::endl;
        ret = false;
    }
    return ret;
}

void SimulControl::infect_command(char *hostname)
{
    /*
    cMessage *msg = new cMessage("Infect host");
    msg->setKind(HOST_INFECTED);
    infect_msg.push_back(msg);
    cGate *inputGate = getSystemModule()->getModuleByPath(hostname)->getSubmodule("tcpApp", 0)->gate("c2_direct");
    this->sendDirect(msg, (simtime_t) delay, 0, inputGate);*/
}

void SimulControl::cure_command(char *hostname)
{/*
    cMessage *msg = new cMessage("Cure host");
    msg->setKind(HOST_NOT_INFECTED);
    infect_msg.push_back(msg);
    cGate *inputGate = getSystemModule()->getModuleByPath(hostname)->getSubmodule("tcpApp", 0)->gate("c2_direct");
    this->sendDirect(msg, (simtime_t) delay, 0, inputGate);*/
}

} /* namespace simbo */

} /* namespace inet */
