//
// This file is part of an OMNeT++/OMNEST simulation example.
//
// Copyright (C) 1992-2015 Andras Varga
//
// This file is distributed WITHOUT ANY WARRANTY. See the file
// `license' for details on this and other legal matters.
//


//
// A real-time interface
//
package inet.applications.simbo.Modulos.Telnet;

simple HTTPClient
{
    parameters:
        int addr;
        int srvAddr;
        volatile double sendIaTime @unit(s);
        @display("i=device/pc2");
    gates:
        inout g;
}



