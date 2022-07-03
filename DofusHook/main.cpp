#include "../lib/Blackbone/src/BlackBone/Process/Process.h"
#include <WS2tcpip.h>
#include <iostream>

#pragma comment(lib, "Ws2_32")

void ApplyHooks(blackbone::Process& proc)
{
	static HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	static SOCKET socket = NULL;

	auto pSend = proc.modules().GetExport(L"Ws2_32.dll", "WSASend");
	auto pRecv = proc.modules().GetExport(L"Ws2_32.dll", "recv");
	auto pConnect = proc.modules().GetExport(L"Ws2_32.dll", "connect");

	proc.hooks().Apply(blackbone::RemoteHook::eHookType::hwbp, pSend->procAddress, [](blackbone::RemoteContext& ctx){
		auto socket = ctx.getArg(0);
		auto lpBuf = ctx.getArg(1);
		auto nBuf = ctx.getArg(2);
		
		for (int i = 0; i < nBuf; i++)
		{
			auto currBuf = ctx.memory().Read<WSABUF>(lpBuf + i * sizeof(WSABUF)).result();
			if (currBuf.len > 3)
			{
				std::vector<char> msg(currBuf.len, 0);
				ctx.memory().Read(blackbone::ptr_t(currBuf.buf), currBuf.len - 2, (void*)msg.data());
				if (std::isalnum(msg[0]))
				{
					SetConsoleTextAttribute(hStdOut, 14);
					std::cout << socket << " > " << msg.data() << std::endl;
					SetConsoleTextAttribute(hStdOut, 15);
				}
			}
		}
	});

	proc.hooks().Apply(blackbone::RemoteHook::eHookType::hwbp, pRecv->procAddress, [](blackbone::RemoteContext& ctx) {}, 0);
	// hook return and check if recv was successful
	proc.hooks().AddReturnHook(pRecv->procAddress, [](blackbone::RemoteContext& ctx) {
		if (auto ret = ctx.native().Rax; ret > 0)
		{
			if (auto len = ctx.getArg(2); len > 0)
			{
				auto socket = ctx.getArg(0);
				auto lpBuf = ctx.getArg(1);
				std::vector<char> msg(len, 0);
				ctx.memory().Read(blackbone::ptr_t(lpBuf), len, (void*)msg.data());
				if (msg[0] != '\0' && std::isalnum(msg[0]))
				{
					SetConsoleTextAttribute(hStdOut, 13);
					std::cout << socket << " < " << msg.data() << std::endl;
					SetConsoleTextAttribute(hStdOut, 15);
				}
			}
		}
	});

	proc.hooks().Apply(blackbone::RemoteHook::eHookType::hwbp, pConnect->procAddress, [](blackbone::RemoteContext& ctx) {
		auto socket = ctx.getArg(0);
		auto pSockAddr = ctx.getArg(1);
		auto addr = ctx.memory().Read<sockaddr_in>(pSockAddr).result();
		if (addr.sin_family == AF_INET)
		{
			char ip[1024]{ 0 };
			InetNtopA(addr.sin_family, (void*)&(addr.sin_addr), ip, sizeof(ip));
			SetConsoleTextAttribute(hStdOut, 10);
			std::wcout << socket << L" [+] Connecting to " << ip << std::endl;
			SetConsoleTextAttribute(hStdOut, 15);
		}
	});
}

int main()
{
	auto pid = blackbone::Process::EnumByName(L"Dofus Retro.exe")[2];
	
	blackbone::Process proc;

	proc.Attach(pid);

	ApplyHooks(proc);

	for (;;) { Sleep(10); }
}
