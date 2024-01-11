/****************************************************************************/
/// @file    Beacon.cc
/// @author  Mani Amoozadeh <maniam@ucdavis.edu>
/// @author  second author name
/// @date    August 2013
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

#include "nodes/vehicle/01_Beacon.h"
#include "baseAppl/ApplToPhyControlInfo.h"
#include "nodes/SCMS/bsmsign.h"
#include "nodes/SCMS/hex_str.h"

namespace VENTOS {

Define_Module(VENTOS::ApplVBeacon);

// Parameters of Pseudo certificate encryption
std::string pca_cert;;
std::string pca_pub_x;
std::string pseudo_cert_7A_0;
std::string pseudo_cert_tbs_7A_0;
std::string pub_recon_x_7A_0;
std::string prv_recon_7A_0;
std::string cert_seed_prv;
std::string cert_exp_val;
std::string pseudo_prv_7A_0;
ECPoint pseudo_pub_7A_0;
//unsigned long long epoch1609Dot2 = 1072915200;
//unsigned long long currTime;
unsigned long long generationTime;

ApplVBeacon::~ApplVBeacon()
{

}


void ApplVBeacon::initialize(int stage)
{
    super::initialize(stage);

    if (stage == 0)
    {
        // set the debug flag in SUMO
        TraCI->vehicleSetDebug(getParentModule()->par("SUMOID").stringValue(), getParentModule()->par("SUMOvehicleDebug").boolValue());

        sonarDist = par("sonarDist").doubleValue();

        SCMS_initialize();
    }
}


void ApplVBeacon::finish()
{
    super::finish();
}


void ApplVBeacon::handleSelfMsg(omnetpp::cMessage* msg)
{
    super::handleSelfMsg(msg);
}


void ApplVBeacon::sendBeacon()
{
    BeaconVehicle* beaconMsg = generateBeacon();

    BSM* bsmMsg = generateBSMMessage(beaconMsg);

    // broadcast the beacon wirelessly using IEEE 802.11p
    //send(beaconMsg, lowerLayerOut);
    send(bsmMsg, lowerLayerOut);
}


BeaconVehicle*  ApplVBeacon::generateBeacon()
{
    BeaconVehicle* wsm = new BeaconVehicle("beaconVehicle", TYPE_BEACON_VEHICLE);

    // add header length
    wsm->addBitLength(headerLength);

    // add payload length
    wsm->addBitLength(beaconLengthBits);

    wsm->setWsmVersion(1);
    wsm->setSecurityType(1);
    wsm->setChannelNumber(Veins::Channels::CCH);
    wsm->setDataRate(1);
    wsm->setPriority(beaconPriority);
    wsm->setPsid(0);
    // wsm->setSerial(serial);
    // wsm->setTimestamp(simTime());

    // fill in the sender/receiver fields
    wsm->setSender(SUMOID.c_str());
    wsm->setSenderType(SUMOType.c_str());
    wsm->setRecipient("broadcast");

    // set current position
    TraCICoord cord = TraCI->vehicleGetPosition(SUMOID);
    wsm->setPos(cord);

    // set current speed
    wsm->setSpeed( TraCI->vehicleGetSpeed(SUMOID) );

    // set current acceleration
    wsm->setAccel( TraCI->vehicleGetCurrentAccel(SUMOID) );

    // set maxDecel
    wsm->setMaxDecel( TraCI->vehicleGetMaxDecel(SUMOID) );

    // set current lane
    wsm->setLane( TraCI->vehicleGetLaneID(SUMOID).c_str() );

    // fill-in the related fields to platoon
    wsm->setPlatoonID(getPlatoonId().c_str());
    wsm->setPlatoonDepth(getPlatoonDepth());

    // set heading -- used in rsu/classify beacons
    wsm->setAngle( TraCI->vehicleGetAngle(SUMOID) );

    return wsm;
}


bool ApplVBeacon::isBeaconFromFrontVehicle(BeaconVehicle* wsm)
{
    auto leader = TraCI->vehicleGetLeader(SUMOID, sonarDist);

    if( leader.leaderID == std::string(wsm->getSender()) )
        return true;
    else
        return false;
}


bool ApplVBeacon::isBeaconFromMyPlatoon(BeaconVehicle* wsm)
{
    if( std::string(wsm->getPlatoonID()) == getPlatoonId())
        return true;
    else
        return false;
}


bool ApplVBeacon::isBeaconFromMyPlatoonLeader(BeaconVehicle* wsm)
{
    // check if a platoon leader is sending this
    if( wsm->getPlatoonDepth() == 0 )
    {
        // check if this is my platoon leader
        if( std::string(wsm->getPlatoonID()) == getPlatoonId())
        {
            // note: we should not check myPlnDepth != 0
            // in predefined platoon, we do not use depth!
            return true;
        }
    }

    return false;
}


std::string ApplVBeacon::getPlatoonId()
{
    throw omnetpp::cRuntimeError("Platoon class should implement this method!");
}


int ApplVBeacon::getPlatoonDepth()
{
    throw omnetpp::cRuntimeError("Platoon class should implement this method!");
}

BSM* ApplVBeacon::generateBSMMessage(BeaconVehicle* wsm)
{

    EV << "------Before Encode--------- " << std::endl;
    EV << "----------------------------- " << std::endl;
    EV << "----------------------------- " << std::endl;
    EV << "sender         : " << wsm->getSender() << std::endl;
    EV << "senderType     : " << wsm->getSenderType() << std::endl;
    EV << "recipient      : " << wsm->getRecipient() << std::endl;
    EV << "pos x          : " << wsm->getPos().x << std::endl;
    EV << "pos y          : " << wsm->getPos().y << std::endl;
    EV << "pos z          : " << wsm->getPos().z << std::endl;
    EV << "speed          : " << wsm->getSpeed() << std::endl;
    EV << "accel          : " << wsm->getAccel() << std::endl;
    EV << "maxDecel       : " << wsm->getMaxDecel() << std::endl;
    EV << "lane           : " << wsm->getLane() << std::endl;
    EV << "platoonID      : " << wsm->getPlatoonID() << std::endl;
    EV << "platoonDepth   : " << wsm->getPlatoonDepth() << std::endl;
    EV << "angle          : " << wsm->getAngle() << std::endl;
    EV << "brakes         : " << wsm->getBrakes() << std::endl;
    EV << "density        : " << wsm->getDensity() << std::endl;
    EV << "----------------------------- " << std::endl;
    EV << "----------------------------- " << std::endl;
    EV << "----------------------------- " << std::endl;

    //////////////////////////////////////////////////////////////////////////////////// start of Pseudo certificate encryption code
    std::string sender = wsm->getSender();
    ECPoint pca_pub("compressed-y-0", pca_pub_x);
    ECPoint pub_recon_7A_0("compressed-y-1", pub_recon_x_7A_0);
    string bsm1_1="";

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Encoding:
    size_t encodedSize = sizeof(wsm); // Replace with actual size calculation
    uint8_t *encodedBuffer = (uint8_t *)malloc(encodedSize);
    memcpy(encodedBuffer, &wsm, encodedSize);
    // Convert encodedBuffer to hex string without spaces
    char hexString[encodedSize * 2 + 1]; // +1 for null terminator
    bytesToHexString(encodedBuffer, encodedSize, hexString);
    bsm1_1 = hexString;

    //EV << "Encoded Buffer (Hex String without spaces)    :"<< hexString << std::endl;
    //EV << "Encoded Buffer bsm (Hex String without spaces):"<< bsm1_1 << std::endl;

    free(encodedBuffer);

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    generationTime = omnetpp::simTime().dbl() * 1000;
    string signedbsm = BSM_encode(generationTime, bsm1_1, pseudo_prv_7A_0, pseudo_cert_7A_0);
    //cout << "Encrypted BSM message = " << signedbsm << endl;
    //////////////////////////////////////////////////////////////////////////////////// end of Pseudo certificate encryption code

    BSM* bsm = new BSM("BSM Vehicle Payload", TYPE_BEACON_BSM);

    // add sender ID
    bsm->setSender(sender.c_str());
    // add header length
    bsm->addBitLength(headerLength);

    // add payload length
    bsm->addBitLength(beaconLengthBits);

    bsm->setWsmVersion(1);
    bsm->setSecurityType(1);
    bsm->setChannelNumber(Veins::Channels::CCH);
    bsm->setDataRate(1);
    bsm->setPriority(beaconPriority);
    bsm->setPsid(0);
    //bsm->setSerial(serial);
    //bsm->setTimestamp(simTime());

    // fill in the payload field
    bsm->setPayload(signedbsm.c_str());

    bsm->setPCA_certificate(pca_cert.c_str());
    bsm->setPseudonym_certificate(pseudo_cert_7A_0.c_str());
    bsm->setPublic_key(pca_pub_x.c_str());

    return bsm;
}

void ApplVBeacon::SCMS_initialize()
{
    pca_cert = R"(8003 0080 fabd 443d bf85 85fa 5981 1676
         3278 7063 612d 7465 7374 2e67 6873 6973
         732e 636f 6d5e 6f5b 0002 18f3 4861 8600
         0a83 0103 8000 7c80 01e4 8003 4801 0180
         0123 8003 8500 0101 0100 8001 0200 0120
         0001 2600 8082 42ac 6bc3 42c4 93d2 a6a8
         2169 fc25 2ebf 6c86 ba6a 3285 b143 2376
         1a43 de15 ff80 8080 827c 5c5a d2e4 4129
         9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
         dd9e 8e39 188f a57f ef80 8000 e93d b970
         f630 d6f5 c4f0 a9e2 7a57 85f1 43e3 e82f
         9090 a76a 882f 08c6 3f79 51ec b93a c48b
         4f5b 6aac b052 35c8 230b 5c2a b624 f0df
         36cb f0f0 2f33 01b9 cf5f 69)";
     pca_cert.erase(remove(pca_cert.begin(), pca_cert.end(), '\n'), pca_cert.end());
     pca_cert.erase(remove(pca_cert.begin(), pca_cert.end(),  ' '), pca_cert.end());

     pca_pub_x = R"(7c 5c5a d2e4 4129
         9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
         dd9e 8e39 188f a57f ef)";
     pca_pub_x.erase(std::remove(pca_pub_x.begin(), pca_pub_x.end(), '\n'), pca_pub_x.end());
     pca_pub_x.erase(std::remove(pca_pub_x.begin(), pca_pub_x.end(),  ' '), pca_pub_x.end());

     pseudo_cert_7A_0 = R"(0003 0180 da76 6b0e 278f d23d 5080 8000
         7a8e 4d44 3b14 03b3 9ffc 0000 000f 8e4d
         443b 1403 b39f fc5e 6f5b 0001 191e 2210
         8400 a983 0103 8000 7c80 01e4 8003 4801
         0200 0120 0001 2681 837a 06e6 dab3 cb6c
         c0b3 7657 1681 7212 3854 690a de9a d8e7
         f1aa 9286 6fc6 c7bd 79)";
     pseudo_cert_7A_0.erase(remove(pseudo_cert_7A_0.begin(), pseudo_cert_7A_0.end(), '\n'), pseudo_cert_7A_0.end());
     pseudo_cert_7A_0.erase(remove(pseudo_cert_7A_0.begin(), pseudo_cert_7A_0.end(),  ' '), pseudo_cert_7A_0.end());

     pseudo_cert_tbs_7A_0 = R"(5080 8000
         7a8e 4d44 3b14 03b3 9ffc 0000 000f 8e4d
         443b 1403 b39f fc5e 6f5b 0001 191e 2210
         8400 a983 0103 8000 7c80 01e4 8003 4801
         0200 0120 0001 2681 837a 06e6 dab3 cb6c
         c0b3 7657 1681 7212 3854 690a de9a d8e7
         f1aa 9286 6fc6 c7bd 79)";
     pseudo_cert_tbs_7A_0.erase(remove(pseudo_cert_tbs_7A_0.begin(), pseudo_cert_tbs_7A_0.end(), '\n'), pseudo_cert_tbs_7A_0.end());
     pseudo_cert_tbs_7A_0.erase(remove(pseudo_cert_tbs_7A_0.begin(), pseudo_cert_tbs_7A_0.end(),  ' '), pseudo_cert_tbs_7A_0.end());

     pub_recon_x_7A_0 = R"(7a 06e6 dab3 cb6c c0b3 7657 1681 7212 3854 690a de9a d8e7 f1aa 9286 6fc6 c7bd 79)";
     pub_recon_x_7A_0.erase(remove(pub_recon_x_7A_0.begin(), pub_recon_x_7A_0.end(), '\n'), pub_recon_x_7A_0.end());
     pub_recon_x_7A_0.erase(remove(pub_recon_x_7A_0.begin(), pub_recon_x_7A_0.end(),  ' '), pub_recon_x_7A_0.end());

     prv_recon_7A_0 = R"(08fa 4ce5 2c68 b12b b8ba f94a 15d5 7aed c82b f842 7997 75ec 520a c28b 31e7 d907)";
     prv_recon_7A_0.erase(remove(prv_recon_7A_0.begin(), prv_recon_7A_0.end(), '\n'), prv_recon_7A_0.end());
     prv_recon_7A_0.erase(remove(prv_recon_7A_0.begin(), prv_recon_7A_0.end(),  ' '), prv_recon_7A_0.end());

     cert_seed_prv = R"(4655 5a86 2db4 4758 e8a9 cbcb b0ab aec6 bf91 d38d ac24 11f5 3f59 1867 4a1c b1ad)";
     cert_seed_prv.erase(remove(cert_seed_prv.begin(), cert_seed_prv.end(), '\n'), cert_seed_prv.end());
     cert_seed_prv.erase(remove(cert_seed_prv.begin(), cert_seed_prv.end(),  ' '), cert_seed_prv.end());

     cert_exp_val = R"(9d53 e9d9 626e 647c edd7 bd6a a7fd e192)";
     cert_exp_val.erase(remove(cert_exp_val.begin(), cert_exp_val.end(), '\n'), cert_exp_val.end());
     cert_exp_val.erase(remove(cert_exp_val.begin(), cert_exp_val.end(),  ' '), cert_exp_val.end());

     tie(pseudo_prv_7A_0, pseudo_pub_7A_0) = BFExpandAndReconstructKey(
         hexStringToCppInt(cert_seed_prv), hexStringToCppInt(cert_exp_val), hexStringToInt("0x7A"), 0,
         prv_recon_7A_0, pseudo_cert_tbs_7A_0, pca_cert);

     EV << "Pseudo Private Key for vehicle("<<  SUMOID <<"): " << pseudo_prv_7A_0 << std::endl;
     EV << "Pseudo Public  Key for vehicle("<<  SUMOID <<"): " << pseudo_pub_7A_0.ecc.name <<":" << pseudo_pub_7A_0.x <<":"<< pseudo_pub_7A_0.y << std::endl;
}

}
