#include <iostream>

int RunPcapWriterTests();
int RunConfigLoaderTests();
int RunLivePolicySmokeTests();
int RunPcapReaderTests();
int RunOfflinePacketFeedTests();
int RunAfPacketCaptureTests();
int RunPacketDecodeTests();
int RunLivePolicyClassificationTests();
int RunLivePolicyQuicTests();
int RunQuicConstrictorTests();
int RunTlsConstrictorTests();

int main() {
    int failures = 0;

    failures += RunPcapWriterTests();
    failures += RunConfigLoaderTests();
    failures += RunLivePolicySmokeTests();
    failures += RunPcapReaderTests();
    failures += RunOfflinePacketFeedTests();
    failures += RunAfPacketCaptureTests();
    failures += RunPacketDecodeTests();
    failures += RunLivePolicyClassificationTests();
    failures += RunLivePolicyQuicTests();
    failures += RunQuicConstrictorTests();
    failures += RunTlsConstrictorTests();

    if (failures == 0) {
        std::cout << "All tests passed.\n";
        return 0;
    }

    std::cerr << failures << " test(s) failed.\n";
    return 1;
}
