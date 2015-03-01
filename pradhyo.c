#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int totalbytes=0; float totaltime=0;
int fiveminbytes[12];
int c0=0,c1=0,c2=0,c3=0,c4=0,c5=0,c6=0;
int totalpackets=0;
int hosts[65500][2];
int ports[12][4]; int portcount=0;
int hports[12][4];
int scount=0;
int dcount=0;
int minute=-1;

int verdict[3500][3500][4];
int hashport;
int ptemp1=-4, ptemp2=-3, ptemp3=-2, ptemp4=-1;
int least;


void readfile(){
    FILE        *f;
    float	timestamp;
    int         shost;
    int		dhost;
    int		sport;
    int		dport;
    int         bytes;

    f = fopen("dec-pkt-1.tcp", "r");

    while( fscanf(f, "%f %d %d %d %d %d \n", &timestamp, &shost, &dhost, &sport, &dport, &bytes) != EOF )
	{

	float time, initialtime;
	totalbytes=totalbytes+40+bytes;
        totalpackets++;
	hosts[shost][0]+=bytes+40;
	hosts[dport][1]+=bytes+40;

	if (ptemp1<=ptemp2 && ptemp1<=ptemp2 && ptemp1<=ptemp3) least=0;
	if (ptemp2<=ptemp1 && ptemp2<=ptemp3 && ptemp2<=ptemp4) least=1;
	if (ptemp3<=ptemp1 && ptemp3<=ptemp2 && ptemp3<=ptemp4) least=2;
	if (ptemp4<=ptemp1 && ptemp4<=ptemp2 && ptemp4<=ptemp3) least=3;

	if (verdict[(shost^dhost)%3233][(sport^dport)%3233][((shost*1099511628211)%3233)%4]>=0)
		hashport=verdict[(shost^dhost)%3233][(sport^dport)%3233][((shost*1099511628211)%3233)%4];
	else
		{
		verdict[(shost^dhost)%3233][(sport^dport)%3233][((shost*1099511628211)%3233)%4]=least;
		hashport=verdict[(shost^dhost)%3233][(sport^dport)%3233][((shost*1099511628211)%3233)%4];
		}
		

	if (hashport==0)
		ptemp1+=bytes;
	if (hashport==1)
		ptemp2+=bytes;	
	if (hashport==2)
		ptemp3+=bytes;	
	if (hashport==3)
		ptemp4+=bytes;

	if (portcount==4)
		{portcount=0;}
	if (bytes==0)
		{		c0++;	}
	else if (bytes<=127)
		{		c1++;	}
        else if (bytes<=255)
		{		c2++;	}
	else if (bytes<=383)
		{		c3++;	}
	else if (bytes<=511)
		{		c4++;	}
	else if (bytes==512)
		{		c5++;	}
	else if (bytes>512)
		{		c6++;	}		
	if (minute<0)
		{
		time = timestamp;
		minute++;	
		initialtime=timestamp;
		scount++;dcount++;		
		}
	else
		{
		totaltime=timestamp-initialtime;
		}
	
	
	if (timestamp<time+300)
		{
		ports[minute][portcount]=ports[minute][portcount]+bytes+40;
		portcount++;
		hports[minute][hashport]=hports[minute][hashport]+bytes+40;
		fiveminbytes[minute]=fiveminbytes[minute]+40+bytes;;
		}
	else	
		{
		minute++;
		time=timestamp;
		ptemp1=4, ptemp2=3, ptemp3=2, ptemp4=1;
		}
	}
}





int main()
{
    	
	int i,i1,i2,i3,i4; float totalaveragebitrate; 
	int smax[3][2],dmax[3][2];
	for(i=0;i<2;i++)
		{
		smax[0][i]=0,smax[1][i]=0,smax[2][i]=0;
		dmax[0][i]=0,dmax[1][i]=0,dmax[2][i]=0;
		}
	for(i=0;i<12;i++)
		{	
		ports[i][0]=0;ports[i][1]=0;ports[i][2]=0;ports[i][3]=0;
		hports[i][0]=0;hports[i][1]=0;hports[i][2]=0;hports[i][3]=0;
		}
	for (i=0;i<100;i++)
		{
		fiveminbytes[i]=0;
		} 
        for (i=0;i<65500;i++)
		{	
		hosts[i][0]=0;
		hosts[i][1]=0;			
		}

	for (i1=0;i1<3500;i1++)
		for (i2=0;i2<3500;i2++)
			for (i3=0;i3<4;i3++)
			{verdict[i1][i2][i3]=-1;}


	readfile();
	totalaveragebitrate=(float)totalbytes/totaltime;
        for (i=0;i<65500;i++)
		{	
		if (hosts[i][0]>smax[0][1])
			{
			smax[0][1]=hosts[i][0]; 
			smax[0][0]=i;
			}
		if (hosts[i][1]>dmax[0][1])
			{
			dmax[0][1]=hosts[i][1]; 
			dmax[0][0]=i;
			}
		}

        for (i=0;i<2900;i++)
		{	
		if ((hosts[i][0]>smax[1][1])&&(i!=smax[0][0]))
			{
			smax[1][1]=hosts[i][0]; 
			smax[1][0]=i;
			}
		if ((hosts[i][1]>dmax[1][1])&&(i!=dmax[0][0]))
			{
			dmax[1][1]=hosts[i][1]; 
			dmax[1][0]=i;
			}
		}        

        for (i=0;i<2900;i++)
		{	
		if ((hosts[i][0]>smax[2][1])&&(i!=smax[0][0])&&(i!=smax[1][0]))
			{
			smax[2][1]=hosts[i][0]; 
			smax[2][0]=i;
			}
		if ((hosts[i][1]>dmax[2][1])&&(i!=dmax[0][0])&&(i!=dmax[1][0]))
			{
			dmax[2][1]=hosts[i][1]; 
			dmax[2][0]=i;
			}
		}        
	printf("Total packets= %d; Total bytes= %d; Total time= %f; ", totalpackets, totalbytes, totaltime);
	printf("Average=%f \n\nPackets by size and Percentage\n0      = %d: %f \n1-127  = %d: %f \n128-255=  %d: %f \n256-383=  %d: %f \n384-511=  %d: %f \n512    = %d: %f \n>512   =  %d: %f\n", 8*totalaveragebitrate/1024, c0, (float) (c0*100)/totalpackets, c1,(float) (c1*100)/totalpackets, c2,(float) (c2*100)/totalpackets, c3,(float) (c3*100)/totalpackets, c4,(float) (c4*100)/totalpackets, c5,(float) (c5*100)/totalpackets, c6,(float) (c6*100)/totalpackets);
	
	printf("\nMax traffic\n");
        for (i=0;i<3;i++)
		{		 
	printf("SAddress: %d Bytes: %d Percent: %f DPort: %d Bytes: %d Percent: %f\n", smax[i][0], smax[i][1], (float) (smax[i][1])/(float) (0.01*totalbytes), dmax[i][0], dmax[i][1], (float) (dmax[i][1])/(float)(0.01*totalbytes)); 
		}

 	printf("\nRound robin for every five minutes (total P1 P2 P3 P4 Max-Min)\n");
	
	for (i=0; i<=minute; i++)
		{
		float lolmax=0.0; float lolmin=80.0;
		float temp=8*(float)fiveminbytes[i]/307200;		
		float temp1= 8*(float)ports[i][0]/307200;
		float temp2= 8*(float)ports[i][1]/307200;		
		float temp3= 8*(float)ports[i][2]/307200;		
		float temp4= 8*(float)ports[i][3]/307200;				
		if (temp1>=temp2 && temp1>=temp3 && temp1>=temp4) lolmax=temp1;
		if (temp2>=temp1 && temp2>=temp3 && temp2>=temp4) lolmax=temp2;
		if (temp3>=temp1 && temp3>=temp2 && temp3>=temp4) lolmax=temp3;
		if (temp4>=temp1 && temp4>=temp2 && temp4>=temp3) lolmax=temp4;

		if (temp1<=temp2 && temp1<=temp2 && temp1<=temp3) lolmin=temp1;
		if (temp2<=temp1 && temp2<=temp3 && temp2<=temp4) lolmin=temp2;
		if (temp3<=temp1 && temp3<=temp2 && temp3<=temp4) lolmin=temp3;
		if (temp4<=temp1 && temp4<=temp2 && temp4<=temp3) lolmin=temp4;

		
		printf(" %d: %f %f %f %f %f %f \n", i+1, temp, temp1, temp2, temp3, temp4, lolmax-lolmin);

		}
	printf("\nLoad balancing- No out of order packets (total P1 P2 P3 P4 Max-Min)\n");
	for (i=0; i<=minute; i++)
		{
		float lolmax=0.0; float lolmin=80.0;
		float temp=8*(float)fiveminbytes[i]/307200;		
		float temp1= 8*(float)hports[i][0]/307200;
		float temp2= 8*(float)hports[i][1]/307200;		
		float temp3= 8*(float)hports[i][2]/307200;		
		float temp4= 8*(float)hports[i][3]/307200;				
		if (temp1>=temp2 && temp1>=temp3 && temp1>=temp4) lolmax=temp1;
		if (temp2>=temp1 && temp2>=temp3 && temp2>=temp4) lolmax=temp2;
		if (temp3>=temp1 && temp3>=temp2 && temp3>=temp4) lolmax=temp3;
		if (temp4>=temp1 && temp4>=temp2 && temp4>=temp3) lolmax=temp4;

		if (temp1<=temp2 && temp1<=temp2 && temp1<=temp3) lolmin=temp1;
		if (temp2<=temp1 && temp2<=temp3 && temp2<=temp4) lolmin=temp2;
		if (temp3<=temp1 && temp3<=temp2 && temp3<=temp4) lolmin=temp3;
		if (temp4<=temp1 && temp4<=temp2 && temp4<=temp3) lolmin=temp4;

		
		printf(" %d: %f %f %f %f %f %f \n", i+1, temp, temp1, temp2, temp3, temp4, lolmax-lolmin);
		
		}
 return 0;       
}
