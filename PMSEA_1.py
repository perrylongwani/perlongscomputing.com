import sys
from random import randint
import time
import tracemalloc

#+++++++++++++++++++++Dataset Simulator+++++++++++++++++++++++++++++++++++++++++++
def simGen(): 
    genx = []
    for x in range(112000,112300):
        genx.append(x)
       
    return genx

#+++++++++++++++++++++Dataset Simulator Ends Here+++++++++++++++++++++++++++++++++++++++++++

start = time.process_time()
tracemalloc.start()
#__________________Encryption Utility Functions Starts Here_____________________________________________

#Function for Public key Value
def pKey(xcode):
    code=len(str(xcode))
    
    f = open("eKey.txt","w")
    f.write(str(code)+"\n")
    f.close()

    return code

#Function for a random key Value
def randv():
    c=randint(1,10)
    
    return c

#Function for prepared data length
def plenx(s):         #parameter is signal to be encrypted
    x=s               #initial signal generated
    y=str(x)          #convert the signal to string
    z=len(y)          #length of the list 
    
    if (z%2==0):
        p=y           #prepared data
    else:
        e=0           #even value we add to the initial signal to make it even
        e_x=str(e)    #convert the even value to string
        p=y+e_x
        
    p_x=len(p)        #the length of the prepared data
    
    return p_x

#Function for prepared data
def predata(s):       #parameter is signal to be encrypted
    x=s               #initial signal generated
    y=str(x)          #convert the signal to string
    z=len(y)          #length of the list 
    
    if (z%2==0):
        p=y           #prepared data
    else:
        e=0           #even value we add to the initial signal to make it even
        e_x=str(e)    #convert the even value to string
        p=y+e_x

    return p

#Function for mean IV
def meaniv(p):      #parameter is signal to be encrypted
    s=predata(p)    #call function to get prepared data
    u=str(s)        #convert into string
    y=list(u)
    l=plenx(u)      # length of prepared data
    
    for i in range (0,l):
        y[i]=int(y[i]) #convert to int

    v=sum(y)        #the sum of prepared data digits
    m=v//l          #the mean IV 
    
    return m

#Function for mean FV
def meanfv(p):      #parameter is signal to be encrypted
    s=predata(p)    #call function to get prepared data
    u=str(s)        #convert into string
    y=list(u)       #convert to a list
    l=plenx(u)      # length of prepared data
    
    for i in range (0,l):
        y[i]=int(y[i]) #convert to int

    v=sum(y)        #the sum of prepared data digits
    m=v%l           #the mean FV 
    
    return m

#Function for sum of header data{sod}
def sod(p):        #parameter is signal to be encrypted
    s=p            #assign the parameter to a local variable
    y=str(s)       #convert into string
    h=""           #initialise the variable
    
    for i in range(3):
        h=h+y[i]

    d=int(h)+int(h) #sum od header information for intrusion and error detection
    
    return d

#Function for pop algorithm 1 st round
def pop_m(p):       #parameter is signal to be encrypted
    s=predata(p)    #call function to get prepared data
    u=str(s)        #convert into string
    y=list(u)       #convert to a list
    l=plenx(u)      # length of prepared data
    
    e=""            #initialise even list
    o=""            #initialise odd list
    
    for i in range(0, l, 2):
        e=str(e)+str(y[i])#even list filled

    for i in range(1, l, 2):
        o=str(o)+str(y[i]) #odd list filled

    d=str(o)+ str(e)# pop data calculated 1st round 
    dx=int(d)     # converted to int
    
    return dx
  
#Function for makeshift algorithm 2 nd round  
def makeshift_m(p): #parameter is signal to be encrypted
    s=predata(p)    #call function to get prepared data
    u=str(s)        #convert into string
    l=plenx(u)      # length of prepared data    
    m=meaniv(p)     #call mean IV
    q=pop_m(p)
    c=randv()       #call pubKey for second random key value
    x=abs(m-c)      #value to shift the digits in the 1 st round data
        
    v=""            #initialise the value 
    
    for i in range(0, l):
        v=str(v)+str(x)

    w=int(v)          # mean values converted back to int
    md=q+w            #makeshift data 2 nd round 
    fm=str(md)+"r"+str(c)+"v" #random values appended
    
    return fm

#Function for encryption finalizer
def encrypto_fx(p):   #parameter is signal to be encrypted
    s=str(p)          #assign a parameter to a variable
    y=str(s)          #convert to string
    rs=len(y)          #length of the parameter
    
    if rs<3:
        return 0
    else:
        s=sod(p)          #call sod function
        m=makeshift_m(p)  #call makeshift function
        md=str(m)
    
        rx= md.index('r')
        re = md.index('v')
       
        
        rn= md[rx+1:re]  #random value sub key 
        mdt=md[0:rx] #makeshift data
    
        v=meaniv(p)       #call mean IV function
        f=meanfv(p)       #call mean FV function
        l=plenx(p)        #call plenx function
        
        k="b"+str(rn)+"a"+str(s)+"c"+str(f)+"d"+str(l)+"f"+str(v)+"e"
        key=int(k,base=16)
        pKey(key)     #pass the len as public key
        ex=str(mdt)+str(key) #with appended key values for decryption and intrusion/error detection function
        exint=int(ex)
        
      
        
       #to be commented
        print("Public key",len(str(key)))
        print("Private key",k)
        print("Private Key Size",sys.getsizeof(key))
        print("Public Key Size",sys.getsizeof(len(str(key))))
        print("Transmitted message Size",sys.getsizeof(ex))
        print("_____________________________________________________________________")
    return exint

#____________________Encryption Utility functions Ends Here_______________________________________________

#____________________Decryption Utility Functions Starts Here_____________________________________________

#Function for user secret key Value
def rusKey():
    f=open("ekey.txt","r")
    d=f.read()
    f.close()
    
    g = open("dKey.txt","w")
    g.write(str(d)+"\n")
    g.close()
    
    g = open("dKey.txt","r")
    dK=int(g.read())
    g.close()

    return dK

#Function for reverse prepared data length
def rplenx(p):      #parameter is signal to be decrypted
    s=p             #assign a parameter to a variable
    y=str(s)        #convert to string
    r=len(y)        #length of the parameter
    px=int(rusKey()) #extract the public key
    w=int(y[r-px:r])     #extract last key digits
    whex=hex(w)[2:] #convert back to hex
    s=str(whex)
    
    # sos= s.index('b')
    # rv = s.index('a')
    # sod = s.index('c')
    fv= s.index('d')
    plenx = s.index('f')
    # iv = s.index('e')
    # eos = s.index('e')
    
    rp= s[fv+1:plenx]
    
    return rp


#Function for reverse mean IV
def rmeaniv(p):     #parameter is signal to be decrypted
    s=p             #assign a parameter to a variable
    y=str(s)        #convert to string
    r=len(y)        #length of the parameter
    px=int(rusKey()) #extract the public key
    w=int(y[r-px:r])     #extract last key digits
    whex=hex(w)[2:] #convert back to hex
    s=str(whex)
    
    # sos= s.index('b')
    # rv = s.index('a')
    # sod = s.index('c')
    #fv= s.index('d')
    plenx = s.index('f')
    iv = s.index('e')
    # eos = s.index('e')
    
    riv= s[plenx+1:iv]
        
    return riv

#Function for reverse mean FV
def rmeanfv(p):     #parameter is signal to be decrypted
    s=p             #assign a parameter to a variable
    y=str(s)        #convert to string
    r=len(y)        #length of the parameter
    px=int(rusKey()) #extract the public key
    w=int(y[r-px:r])    #extract last key digits
    whex=hex(w)[2:] #convert back to hex
    s=str(whex)
    
    # sos= s.index('b')
    # rv = s.index('a')
    sod = s.index('c')
    fv= s.index('d')
    #plenx = s.index('f')
    # iv = s.index('e')
    # eos = s.index('e')
    
    rfv= s[sod+1:fv]
    
    return rfv

#Function for reverse random value
def rrandv(p):     #parameter is signal to be decrypted
    s=p             #assign a parameter to a variable
    y=str(s)        #convert to string
    r=len(y)        #length of the parameter
    px=int(rusKey()) #extract the public key
    w=int(y[r-px:r])     #extract last key digits
    whex=hex(w)[2:] #convert back to hex
    s=str(whex)
    
    sos= s.index('b')
    rv = s.index('a')
    # sod = s.index('c')
    #fv= s.index('d')
    #plenx = s.index('f')
    # iv = s.index('e')
    # eos = s.index('e')
    
    rvn= s[sos+1:rv]
    
    return rvn

#Function for reverse sod
def rsod(p):        #parameter is signal to be decrypted
    s=p             #assign a parameter to a variable
    y=str(s)        #convert to string
    r=len(y)        #length of the parameter
    px=int(rusKey()) #extract the public key
    w=int(y[r-px:r])     #extract last key digits
    whex=hex(w)[2:] #convert back to hex
    s=str(whex)
    
    # sos= s.index('b')
    rv = s.index('a')
    sod = s.index('c')
    #fv= s.index('d')
    #plenx = s.index('f')
    # iv = s.index('e')
    # eos = s.index('e')
    
    rsod= s[rv+1:sod]
    
    return rsod

#Function for extracted prepared data from encrpted data
def rmakeshiftdata(p):    #parameter is signal to be decrypted prepared data
    s=p             #assign a parameter to a variable
    y=str(s)        #convert to string
    r=len(y)        #length of the parameter
    px=int(rusKey()) #extract the public key
    w=int(y[0:r-px])     #extract last key digits
    rmdata=w
    
    return rmdata

#Function for reverse makeshift function
def rmakeshift_m(p):         #parameter is signal to be decrypted
    s=p                      #assign parameter to a variable
    y=str(s)                 #convert to string
    m=int(rmeaniv(s))        #extracting mean IV
    c=int(rrandv(y))         #call randv for second random key value
    y=abs(m-c)               #preparing the reverse
    p=int(rplenx(s))         #extracting plenx
    z=int(rmakeshiftdata(s)) #extracting rmakeshift data
    x=""                     #iniialising a variable
    rm=0
    
    for i in range(0, p):
          x=str(x)+str(y)
          rm=int(x)
    dp=z-rm                 #extracting pop data
    
    return dp

#Function for reverse pop function
def rpop_m(p):            #parameter is signal to be decrypted
    s=p                   #assign parameter to a variable
    y=abs(rmakeshift_m(s))#calling the rmakeshift function
    q=str(y)              #convert to string
    e=""                  #initialise the variable
    o=""                  #initialise the variable
    r=len(q)//2
    
    for i in range(0,r):
        o=o+q[i]+str(0)  #odd pop index
    #remove the last digit
    so=""
    for i in range(0,len(o)-1):
        so=so+o[i]
   
    for i in range(r,r*2):
          e=e+q[i]+str(0) #even pop index 
    rp=(int(e)+int(so)) #extracting original signal
    sp=str(rp)
    
    if ((sp[-1]=="0") and (len(sp)>6)):      #last digits if zero then it is even value need to be droppedt
        pd=""
        for i in range(0,len(sp)-1):
            pd=pd+sp[i]
    else:
        pd=rp
            
    return pd

# Function for decryption finalizer function
def decrypto_fx(p):            #parameter is signal to be decrypted
    s=p                        #assign the parameter to variable
    y=str(s)                   #convert to string
    r=len(y)                   #length of the parameter
    
    if r<13:
        return 0
    else:
        m=rpop_m(y)                #call reverse pop function
        #g=sod(m)                  #call sod function
        g=[224,226,228,230]        #Four Fields 112,113,114,115
        h=plenx(m)                 #call plenx function
        t=int(rplenx(s))           #call the reverse plenx function
        z=int(rsod(s))             #call the reverse sod function
        w=int(rmeaniv(s))          #call the reverse mean IV function
        x=int(meanfv(m))           #call the mean FV function
        c=int(meaniv(m))           #call the mean IV function
        ds=rpop_m(s)               #call reverse pop function to decrypt the encrypted data
        f=int(rmeanfv(s))          #call mean FV function
        
        fx=""                      #initialise a variable


        if not (z in(g) )and (h==t and w==c and f==x):
            fx="Intrusion Detected!!!"
            print("TX:",ds)
            print("SOD:",g,"MEANIV:",c,"MEANFV:",x,"PLENX:",h)
            print("RSOD:",z,"RMEANIV:",w,"RMEANFV:",f,"RPLENX:",t)
                             
        elif (not (z in(g)) and (h!=t and w!=c and f!=x) or ((z in(g)) and h!=t or  w!=c or  f!=x)):
            fx="Errors Detection!!!"
            print("TX:",ds)
            print("SOD:",g,"MEANIV:",c,"MEANFV:",x,"PLENX:",h)
            print("RSOD:",z,"RMEANIV:",w,"RMEANFV:",f,"RPLENX:",t)
            
        elif ((z in(g)) and h==t and w==c and f==x):
            fx=ds
            print("TX:",ds)
            print("SOD:",g,"MEANIV:",c,"MEANFV:",x,"PLENX:",h)
            print("RSOD:",z,"RMEANIV:",w,"RMEANFV:",f,"RPLENX:",t)
        else:
            fx="Errors Detection!!!"
            print("TX:",ds)
            print("SOD:",g,"MEANIV:",c,"MEANFV:",x,"PLENX:",h)
            print("RSOD:",z,"RMEANIV:",w,"RMEANFV:",f,"RPLENX:",t)
    
    return fx

#_____________________________________________Decryption Utility functions Ends Here______________________

#*************************************Encryption Function*************************************************

def encryption_m(ix):               #parameter is signal to be encrypted
    print("_____________________________________________________________________")
    print("")
    encrypto_tx=encrypto_fx(ix)     #call encrypto finalizer
    
    if encrypto_tx!=0:
        print("Plain_Signal: ", ix)
        print("encrpted_Signal: ", encrypto_tx)
        print("_____________________________________________________________________")
    else:
         print("")
         print("{scantError} {Intrusion Detected}")
         print("_____________________________________________________________________")
      
# #*************************************Decryption Function**********************************************
def decryption_m(p):                #parameter is signal to be decrypted
    s=int(p)                        #assign the parameter to variable
    decrypto_tx=decrypto_fx(s)      #call the decrypto finaliser
  
    
    if decrypto_tx!=0:
        print("_____________________________________________________________________")
        print("")
        print("encrpted_Signal: ",s )
        print("Decrypted Signal: ", decrypto_tx)
        print("_____________________________________________________________________")
    else:
        print("")
        print("{DecryptoError} Intrusion Detected")
        print("_____________________________________________________________________")
   
#*************************************Main Function******************************************************

def main():
    mode=input("Enter the communication mode for cryptograpgh(T:Sending, R: Receiving) or (A) for Analysis: ")
    if ((mode=="T") or (mode=="t")):
        genx=simGen()
        geny=str(genx[0:1:1])[1:-1]#input("Enter or generate a signal: ")from a list
        signal=geny
        encryption_m(signal)             
    elif ((mode=="R") or (mode=="r")):
        encrypted=input("Enter or receive the encrypted signal: ")
        decryption_m(encrypted)
    elif mode=="a":
        analytics()
    else:
        print("Listening.......")  

#***************************************Analysis Area***************************************************  

def analytics():
    elapsed = (time.process_time() - start)
    execution_time=float(elapsed)
    algorithm_clock=round(execution_time,2)
   
# encryption methods
    typ=input("Are you Analyzing encryption or decryption? (E/D):")
    if typ=="e":
        eix=input("enter the input value:")
        a=sys.getsizeof(eix)
        b=sys.getsizeof(randv())
        c=sys.getsizeof(plenx(eix))
        d=sys.getsizeof(predata(eix))
        e=sys.getsizeof(meaniv(eix))
        f=sys.getsizeof(meanfv(eix))
        g=sys.getsizeof(sod(eix))
        h=sys.getsizeof(pop_m(eix))
        i=sys.getsizeof(makeshift_m(eix))
        j=sys.getsizeof(encrypto_fx(eix))
        k=sys.getsizeof(encryption_m(eix))
    
        
        encryption_sum=a+b+c+d+e+f+g+h+i+j+k
        throughtputex=round(((a*0.008)/algorithm_clock),2)
        software_effex=round((throughtputex/(encryption_sum*0.001)),2)
        CPU_use=algorithm_clock*100
     
        print("Encryption Analytics")
        print("_____________________________________________________________________")
        print("--- %s Bytes ]" %f"The Input Size is ---[ {a}")
        print("--- %s Bytes ]" %f"The Total Encryption Algorihm Code Size is ---[ {encryption_sum}")
        print("--- %s seconds ]" % f"Runtime of the algorithm is ---[ {algorithm_clock}")
        print("--- %s Kbps ]" %f"The Throughput of Encryption Algorihm is ---[ {throughtputex}")
        print("--- %s Kbps/KB ]" %f"The Software efficiency of Encryption Algorihm is ---[ {software_effex}")
        print("--- %s Percent ]" %f"The CPU Usage of the Encryption Algorithm  is ---[ {CPU_use}")
        print("--- The Memory usage is",tracemalloc.get_traced_memory())
    elif typ=="d":
        dix=input("enter the input value:")
        a=sys.getsizeof(dix)
        b=sys.getsizeof(rusKey())
        c=sys.getsizeof(rplenx(dix))
        d=sys.getsizeof(rmeaniv(dix))
        e=sys.getsizeof(rmeanfv(dix))
        f=sys.getsizeof(rrandv(dix))
        g=sys.getsizeof(rsod(dix))
        h=sys.getsizeof(rmakeshiftdata(dix))
        i=sys.getsizeof(rmakeshift_m(dix))
        j=sys.getsizeof(decrypto_fx(dix))
        k=sys.getsizeof(rpop_m(dix))
        l=sys.getsizeof(decryption_m(dix))
   
        
        encryption_sum=a+b+c+d+e+f+g+h+i+j+k+l
        throughtputex=round(((a*0.008)/algorithm_clock),2)
        software_effex=round((throughtputex/(encryption_sum*0.001)),2)
        CPU_use=algorithm_clock*100
        
        print("Decryption Analytics")
        print("_____________________________________________________________________")
     
        print("--- %s Bytes ]" %f"The Input Size is ---[ {a}")
        print("--- %s Bytes ]" %f"The Total Encryption Algorihm Code Size is ---[ {encryption_sum}")
        print("--- %s seconds ]" % f"Runtime of the algorithm is ---[ {algorithm_clock}")
        print("--- %s Kbps ]" %f"The Throughput of Encryption Algorihm is ---[ {throughtputex}")
        print("--- %s Kbps/KB ]" %f"The Software efficiency of Encryption Algorihm is ---[ {software_effex}")
        print("--- %s Percent ]" %f"The CPU Usage of the Encryption Algorithm  is ---[ {CPU_use}")
        print("--- The Memory usage is",tracemalloc.get_traced_memory())
    
    return 0
main()






