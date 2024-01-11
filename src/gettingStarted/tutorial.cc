/****************************************************************************/
/// @file    tutorial.cc
/// @author  Mani Amoozadeh <maniam@ucdavis.edu>
/// @author  second author name
/// @date    Sep 2016
///
/****************************************************************************/
// VENTOS, Vehicular Network Open Simulator; see http:?
// Copyright (C) 2013-2015
/****************************************************************************/
//
// This file is part of VENTOS.
// VENTOS is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "tutorial.h"  // including the header file above

namespace VENTOS {

// Define_Module macro registers this class with OMNET++
Define_Module(VENTOS::tutorial);

tutorial::~tutorial()
{

}

void tutorial::initialize(int stage)
{
    if(stage == 0)
    {
        active = par("active").boolValue();

        if(active)
        {
            // get a pointer to the TraCI module
            TraCI = TraCI_Commands::getTraCI();

            // subscribe to initializeWithTraCISignal
            Signal_initialize_withTraCI = registerSignal("initializeWithTraCISignal");
            omnetpp::getSimulation()->getSystemModule()->subscribe("initializeWithTraCISignal", this);

            // subscribe to executeEachTimeStepSignal
            Signal_executeEachTS = registerSignal("executeEachTimeStepSignal");
            omnetpp::getSimulation()->getSystemModule()->subscribe("executeEachTimeStepSignal", this);
        }
    }
}

void tutorial::finish()
{
    if(!active)
        return;

    // unsubscribe from initializeWithTraCISignal
    if(omnetpp::getSimulation()->getSystemModule()->isSubscribed("initializeWithTraCISignal", this))
        omnetpp::getSimulation()->getSystemModule()->unsubscribe("initializeWithTraCISignal", this);

    // unsubscribe from executeEachTimeStepSignal
    if(omnetpp::getSimulation()->getSystemModule()->isSubscribed("executeEachTimeStepSignal", this))
        omnetpp::getSimulation()->getSystemModule()->unsubscribe("executeEachTimeStepSignal", this);
}

void tutorial::handleMessage(omnetpp::cMessage *msg)
{

}

void tutorial::receiveSignal(omnetpp::cComponent *source, omnetpp::simsignal_t signalID, long i, cObject* details)
{
    Enter_Method_Silent();

    // if Signal_executeEachTS is received, then call executeEachTimestep() method
    if(signalID == Signal_executeEachTS)
    {
        tutorial::executeEachTimestep();
    }
    // if Signal_initialize_withTraCI is received, then call initialize_withTraCI() method
    else if(signalID == Signal_initialize_withTraCI)
    {
        tutorial::initialize_withTraCI();
    }
}

void tutorial::initialize_withTraCI()
{

}

void tutorial::executeEachTimestep()
{

}
}
