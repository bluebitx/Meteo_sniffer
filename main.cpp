/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cppFiles/main.cc to edit this template
 */

/* 
 * File:   main.cpp
 * Author: bluebit
 *
 * Created on 20 maja 2024, 15:10
 */

#include <cstdlib>
#include <stdio.h>
#include <cstring>
#include <mysql.h>

using namespace std;
char buff[1024];
char get[1024];
char data[2][50][50];
MYSQL *mysql_con;
/*
 * 
 */
int main(int argc, char** argv) {
    
    printf("wheater sniffer v1.0 author: Bartosz 'BlueBit' Jaszul \r\n");
    
     //Init connection with mysql database (mariadb)
    mysql_con = mysql_init(NULL);
    
    if (mysql_con == NULL){
        printf("Database error - Init fail\r\n");       
        return (EXIT_FAILURE);
    }
    
    char debug=0;
    if (argc >= 2){
        if (strncmp(argv[1],"-v",2)==0)debug=1;
        if (strncmp(argv[1],"-h",2)==0){printf("Application dump data from sainlogic meto station - and put data into database,\r\nIf You use this program - please send me an email to \"bjaszul@gmail.com\"\r\n" );return (EXIT_SUCCESS);}
    }
    
    while(1){
        if ( (system("tcpdump -i eth0 -A 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 and host 192.168.5.40' -c 1 -w x.pcap")<0) ){
            printf ("TCP dump return error - aborting....\r\n");
        }else{
        //if (1){
            printf ("TCP dump done - checking writed file\r\n");
            FILE *fp;
            fp = fopen("x.pcap","r");
            fseek(fp,0,SEEK_END);
            unsigned int len = ftell(fp);
            rewind(fp);
            unsigned int i=0;
            unsigned char byte;
            if ((len < 1024) && ( len > 100 )){ //if len is smaller than buffer
                printf("File len : %d\r\n",len);
                fread(buff,1,len,fp);
                int start;
                for(start=0;start<len-3;start++){
                    if ( (buff[start]=='G') && (buff[start+1]=='E') && (buff[start+2]=='T') )break;
                }
                printf("0\r\n");
                start += 5;
                int stop;
                for (stop = start; stop < len ; stop ++){
                    if (buff[stop]==' ')break;
                }
                
                strncpy(get,buff+start,stop-start);
                get[stop-start]=0;
                
                printf("1\r\n");
                printf("GET : %s\r\n",get);
                int poczatek = 0;
                int koniec =0;
                char parametr[50];
                printf("\r\n\r\n");
                int parametr_i=0;
                printf("2\r\n");
                for ( int i = 0 ; i < strlen(get); i++ ){                
                    if ( poczatek == 0 ){
                        if ( get[i] == '&' )poczatek=i+1;
                         printf("2 1\r\n");
                    }else{
                        if ( get[i] == '&' ){
                            koniec=i;
                             printf("2 2\r\n");
                            strncpy(parametr,get + poczatek,koniec-poczatek);
                             printf("2 3\r\n");
                            parametr[koniec-poczatek]=0;
                            //printf("%s\r\n",parametr);
                             printf("2 4 %s\r\n",parametr);
                            strncpy(&data[0][parametr_i][0],parametr,strstr(parametr,"=")-parametr);
                             printf("2 5\r\n");
                            strcpy(&data[1][parametr_i][0],&parametr[strstr(parametr,"=")+1-parametr]);
                             printf("2 6\r\n");
                            parametr_i++;
                            poczatek=0;
                            i-=1;
                        }
                    }
                }
                printf("3\r\n");
                mysql_con = mysql_init(NULL);
                if (mysql_real_connect(mysql_con,"192.168.5.1","piec2","OguqDaFwEnXg8Hrd","piec2", 0, NULL,0)==NULL){
                    printf("Database error - Connection fail\r\n");
                    mysql_close(mysql_con); 
                    return (EXIT_FAILURE);
                }else{
                    printf("Database - connected\r\n");
                }

                printf("Zdekodowane \r\n");
                for (int i=0;i<parametr_i;i++){
                    printf("%d.%s --> %s \t\t",i+1,data[0][i],data[1][i]);
                    if (i%5==0)printf("\r\n");
                }
                char query[500];
                snprintf(query,sizeof(query),"INSERT INTO weather(`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`,`%s`) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\",\"%s\",\"%s\" );",
                        data[0][1],data[0][2],data[0][3],data[0][4],data[0][5],data[0][6],data[0][7],data[0][8],data[0][9],data[0][10],data[0][11],data[0][12],data[0][13],data[0][14],data[0][15],data[0][16],data[0][17],data[0][18],data[0][19],data[0][20],data[0][21],data[0][22],data[0][23],data[0][24],data[0][25],data[0][26],data[0][27],data[0][28],data[0][29],data[0][30],data[0][31],data[0][32],
                        data[1][1],data[1][2],data[1][3],data[1][4],data[1][5],data[1][6],data[1][7],data[1][8],data[1][9],data[1][10],data[1][11],data[1][12],data[1][13],data[1][14],data[1][15],data[1][16],data[1][17],data[1][18],data[1][19],data[1][20],data[1][21],data[1][22],data[1][23],data[1][24],data[1][25],data[1][26],data[1][27],data[1][28],data[1][29],data[1][30],data[1][31],data[1][32]);
                if (debug)printf("query = %s\r\n",query);
                if (debug)printf("Wsadzam do bazy \r\n");
                if (mysql_query(mysql_con,query)){
                    printf("Error on putting data to database ... aborting (%s) \r\n",mysql_error(mysql_con));
                    mysql_close(mysql_con);
                    return (EXIT_FAILURE);
                }else{
                    printf("Data in database \r\n");
                }    
                
                mysql_close(mysql_con);

            }else{
                printf("Buffer is to small len = %d bytes\r\n",len);
                return (EXIT_FAILURE);
            }
            fclose(fp);
        }//if tcpdump
    }//while1

    return 0;
}

