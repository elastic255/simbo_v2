/*
 * SimulControl.h
 *
 *  Created on: Apr 19, 2018
 *      Author: fabio
 */

#ifndef INET_APPLICATIONS_SIMBO_CLASSES_SIMULCONTROL_SIMULCONTROL_H_
#define INET_APPLICATIONS_SIMBO_CLASSES_SIMULCONTROL_SIMULCONTROL_H_

namespace inet {

namespace simbo {

class SimulControl {
public:
    SimulControl();
    virtual ~SimulControl();

    // Methods to control simulation parameters
    // It can also be used to trigger an infection on a host
    virtual bool read_command(char *command);

    // Infect or cure a host (simulation parameters)
    void infect_command(char *hostname);
    void cure_command(char *hostname);
    //void addHost_command(char *hostname);
};

} /* namespace simbo */

} /* namespace inet */

#endif /* INET_APPLICATIONS_SIMBO_CLASSES_SIMULCONTROL_SIMULCONTROL_H_ */
