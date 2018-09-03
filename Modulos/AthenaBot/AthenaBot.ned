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

package inet.applications.simbo.Modulos.AthenaBot;

import inet.applications.contract.ITCPApp;

simple AthenaBot like ITCPApp
{
    parameters:        
        bool infected = default(true);
        double botActivationTime @unit("s") = default(exponential(1800s));
        double botPingTime @unit("s") = default(60s);
        string serverName = default("");
        string botProtocol = default("http");
        string dosModule = default("yes");
        string downloadModule = default("yes");
        string IP = default("69.178.85.15");
        string outputFilename = default("/home/fabio/Documentos/bot_5");
        string outputFilename_net = default("/home/fabio/Documentos/net_5");
        string pathFiles = default("/run/media/fabio/Dados/Linux/PIBIC/pcap/maccdc2010_00000_20100310205651/");
        bool admin = default(true);
        bool x64 = default(true);
        bool laptop = default(false);
        string dotnet = default("N/A");
        int CPUs = default(2);
        string OS = default("Windows XP");
        //string path;
        @display("i=block/app");
    gates:
        input tcpIn;
        output tcpOut;
        input c2_direct;
}
