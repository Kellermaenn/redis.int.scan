# -*- coding: UTF-8 -*-
import sys,socket,time,Queue,threading,optparse
#author thewind
#mail: wang1241202#163.com
#扫描ip地址(掩码24)redis未授权访问漏洞

def Time():
    return time.strftime('%H:%M:%S')

class ScannerRedis(object):
    def __init__(self,ip,threads):
        self._ip = ip
        self._threads = threads  #线程数
        self._queue = Queue.Queue()
        self._port = 6379
        
    def IpQueue(self):  #生成ip地址段的ip
        temp = self._ip.split('.')
        if(len(temp)!=4):
            print '[%s][+] Please input a current ip ...'%Time()
            sys.exit(0)
        else:
            temp = temp[0]+'.'+temp[1]+'.'+temp[2]+'.'
            for j in range(1,255,1):
                te = temp+str(j)
                self._queue.put(te)
                self._queueNum = self._queue.qsize()
    def Poc(self):  #测试Poc
        result = open('result.txt','w+')
        payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
               
        while not self._queue.empty():
            try:
                s = socket.socket()
                socket.setdefaulttimeout(2)            
                ip = self._queue.get()
                print '[%s][+] %s is Testing ...'%(Time(),ip)
                s.connect((ip,self._port))
                s.send(payload)
                data = s.recv(1024)
                if 'redis_version' in data:
                    result.write(ip)
                    result.write('\r\n')
                    result.flush()
            except KeyboardInterrupt:
                print 'exiting'
                sys.exit(1)
            except:
                pass
            s.close()
        result.close()    
        
    def Threads(self):#线程
        threads = []
        try:
            for i in range(0,int(self._threads),1):
                i = threading.Thread(target=self.Poc,args=())
                threads.append(i)
            for k in threads:
                k.setDaemon(True)
                k.start()
            #k.join()
            while 1:
                alive = False
                for i in threads:
                    alive = alive or i.isAlive()
                    
                if not alive:
                    break
        except KeyboardInterrupt:
            print '\r\n\r\nTask is exiting'
            sys.exit(1)       
        except :
            pass
    def run(self):
        self.IpQueue()
        self.Threads()
        
if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option(
        '-i', '--ip', dest='ip',
        help='target ip')    
    parser.add_option(
    '-t','--threads',dest='num',
    help='threads number'
    )
    opts, args = parser.parse_args()
    if len(sys.argv) == 1 or len(args) > 0:
        parser.print_help()
        exit()    
    scan = ScannerRedis(opts.ip,opts.num)
    try:
        scan.run()
        print '[+]Onlne in result.txt'
        
    except KeyboardInterrupt:
        print 'quit'
        sys.exit(1)    
