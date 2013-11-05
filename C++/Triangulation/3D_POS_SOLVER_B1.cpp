   /* Copyright 2012 
 James Benjamin Harris
 3D POSITION CPP SOLVER
 james.ben.harris@gmail.com
 10/31/2012
*/

/* Standard C++ includes */
#include <stdlib.h>
#include <iostream>
#include <math.h>
#include <stdio.h>
#include <iomanip>
#include <Eigen/Dense>

/*
  Include directly the different
  headers from cppconn/ and mysql_driver.h + mysql_util.h
  (and mysql_connection.h). This will reduce your build time!
*/
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>


struct triangle{
    struct datas {
        std::string MAC;
        double DISTANCE;
        double X;
        double Y;
        double Z;
    } client_data[7];
} client_locations[50];

using namespace std;
using namespace Eigen;

int main(void)
{
cout << endl;
try {
  sql::Driver *driver;
  sql::Connection *con;
  sql::Statement *stmt;
  sql::ResultSet *res;

  /* Create a connection */
  driver = get_driver_instance();
  con = driver->connect("tcp://10.10.10.3:3306", "root", "clbgjc");
  /* Connect to the MySQL test database */
  con->setSchema("PECKHAM_RAW_DATA");
  int i = 0;
  int j = 0;
    Matrix3f A;
    Vector3f b;
  std::string mac_current;
  stmt = con->createStatement();
  res = stmt->executeQuery("SELECT COUNT(MAC_ROUTER), MAC_CLIENT, MAC_ROUTER,AVG(`SIGNAL`), `ROUTERS`.`ROUTER_POSITION_X`,`ROUTERS`.`ROUTER_POSITION_Y`,`ROUTERS`.`ROUTER_POSITION_Z` FROM PECKHAM_RAW_DATA.RAW_PACKET_INFO JOIN PECKHAM_RAW_DATA.ROUTERS ON `ROUTERS`.`ROUTER_MAC` = `RAW_PACKET_INFO`.`MAC_ROUTER` WHERE `RAW_PACKET_INFO`.DT > NOW()-INTERVAL 1 second GROUP BY MAC_CLIENT,MAC_ROUTER ORDER BY MAC_CLIENT");
  while (res->next()) {
      if (i == 0 and j == 0) {
          mac_current = res->getString(2);
          cout<< mac_current <<"|0|"<<j<<"\n";
          client_locations[i].client_data[j].MAC = res->getString(2);
          client_locations[i].client_data[j].DISTANCE = pow ((100/ pow(10,((atof(res->getString(4).c_str()))/10)) ) * (pow ((0.404262661 / (4*3.14159265)),2)),(1/2.9));
          client_locations[i].client_data[j].X = atof(res->getString(5).c_str());
          client_locations[i].client_data[j].Y = atof(res->getString(6).c_str());
          client_locations[i].client_data[j].Z = atof(res->getString(7).c_str());
          j++;
      }
      else{
          if (mac_current == res->getString(2)){
              j++;
              cout<< mac_current <<"|1|"<<j<<"\n";
              client_locations[i].client_data[j].MAC = res->getString(2);
              client_locations[i].client_data[j].DISTANCE = pow ((100/ pow(10,((atof(res->getString(4).c_str()))/10)) ) * (pow ((0.404262661 / (4*3.14159265)),2)),(1/2.9));
              client_locations[i].client_data[j].X = atof(res->getString(5).c_str());
              client_locations[i].client_data[j].Y = atof(res->getString(6).c_str());
              client_locations[i].client_data[j].Z = atof(res->getString(7).c_str());
          }
          else {
              i++;
              j = 0;
              mac_current = res->getString(2);
              cout<< mac_current <<"|2|"<<j<<"\n";
              client_locations[i].client_data[j].MAC = res->getString(2);
              client_locations[i].client_data[j].DISTANCE = pow ((100/ pow(10,((atof(res->getString(4).c_str()))/10)) ) * (pow ((0.404262661 / (4*3.14159265)),2)),(1/2.9));
              client_locations[i].client_data[j].X = atof(res->getString(5).c_str());
              client_locations[i].client_data[j].Y = atof(res->getString(6).c_str());
              client_locations[i].client_data[j].Z = atof(res->getString(7).c_str());
          }
      }
  }
    
    for (i = 0; i <= 50; i++){
        if (client_locations[i].client_data[0].DISTANCE != 0 && client_locations[i].client_data[1].DISTANCE != 0 && client_locations[i].client_data[2].DISTANCE != 0)
        {
            Matrix3f A;
            Vector3f b;
            A << client_locations[i].client_data[0].X,client_locations[i].client_data[0].Y,client_locations[i].client_data[0].Z,  client_locations[i].client_data[1].X,client_locations[i].client_data[1].Y,client_locations[i].client_data[1].Z,  client_locations[i].client_data[2].X,client_locations[i].client_data[2].Y,client_locations[i].client_data[2].Z;
            b << client_locations[i].client_data[0].DISTANCE,client_locations[i].client_data[1].DISTANCE,client_locations[i].client_data[2].DISTANCE;
            Vector3f x = A.colPivHouseholderQr().solve(b);
            cout << "Here is the vector b:\n" << b << endl;
            cout << "The Position for: "<<client_locations[i].client_data[0].MAC<<"\n" << x << endl;
        }
    }
    
  delete res;
  delete stmt;
  delete con;

} catch (sql::SQLException &e) {
  cout << "# ERR: SQLException in " << __FILE__;
  cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
  cout << "# ERR: " << e.what();
  cout << " (MySQL error code: " << e.getErrorCode();
  cout << ", SQLState: " << e.getSQLState() << " )" << endl;
}

cout << endl;

return EXIT_SUCCESS;
}
