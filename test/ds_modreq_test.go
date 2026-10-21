package test_test

// Throwaway experiment for carlhus/DualSteer#16: what does a UE-initiated
// PDU Session Modification Request that only carries a DualSteer report do to
// the SMF data path and the UPF rules? Not meant to be merged.
//
// Each test walks the same script and differs only in the ModReq it sends:
//
//	establish -> ping -> ModReq #1 -> ping -> ModReq #2 -> ping
//	-> AN release -> Service Request -> ping -> UE-initiated release
//
// SMF state is printed by the DSPROBE log in smf (research/ds-modreq-probe),
// UPF state by reading /proc/gtp5g, and PFCP by test.sh -o pcaps.

import (
	"encoding/hex"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	nasIE "github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapIE "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/sctp"
	"github.com/stretchr/testify/require"

	"test"
	"test/nasTestpacket"
	"test/ngapTestpacket"
)

const dsPSI = 10

var sNssaiDS = models.Snssai{Sst: 1, Sd: "fedcba"}

// modReqNoEPCO is a bare ModReq, the shape the existing helper produces.
func modReqNoEPCO() []byte {
	return nasTestpacket.GetPduSessionModificationRequest(dsPSI)
}

// modReqKnownEPCO carries an ePCO with a container nas v1.3.0 can encode.
func modReqKnownEPCO() []byte {
	b, err := (&nasMessage.PDUSessModReq{
		PDUSessId: dsPSI,
		PTI:       0x01,
		ExtendedProtCfgOpts: &nasIE.ExtendedProtCfgOpts{
			FromMs: &nasIE.ExtCfgOptFromMs{DNSV4Req: true},
		},
	}).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

// modReqOperatorEPCO appends a hand-built ePCO holding one operator-specific
// container (FF00H, contents "DS01"), the shape ADR-0003 wants for a DS report.
// nas v1.3.0 cannot encode this, so the IE is spliced in as raw bytes.
func modReqOperatorEPCO() []byte {
	b, err := (&nasMessage.PDUSessModReq{PDUSessId: dsPSI, PTI: 0x01}).MarshalBinary()
	if err != nil {
		panic(err)
	}
	contents := []byte{0x80, 0xff, 0x00, 0x04, 'D', 'S', '0', '1'}
	ie := append([]byte{0x7b, 0x00, byte(len(contents))}, contents...)
	return append(b, ie...)
}

func ulNASTransportSM(payload []byte) []byte {
	b, err := (&nasMessage.ULNASTransport{
		PayloadCntrType: &nasIE.PayloadCntrType{Value: nasIE.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &nasIE.PayloadCntr{Contents: payload},
		PDUSessID:       &nasIE.PDUSessId2{Value: dsPSI},
	}).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func dsMark(t *testing.T, step string) {
	t.Logf("DSSTEP %s %s", time.Now().Format("15:04:05.000000"), step)
}

func dsSendNAS(t *testing.T, ue *test.RanUeContext, conn *sctp.SCTPConn, pdu []byte) {
	pdu, err := test.EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	require.Nil(t, err)
	sendMsg, err := test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	require.Nil(t, err)
	_, err = conn.Write(sendMsg)
	require.Nil(t, err)
}

func dsRecv(t *testing.T, conn *sctp.SCTPConn) ngapMessage.Message {
	recvMsg := make([]byte, 4096)
	n, err := conn.Read(recvMsg)
	require.Nil(t, err)
	m, err := ngapMessage.Parse(recvMsg[:n])
	require.Nil(t, err)
	return m
}

// dsGSM decodes the 5GSM message carried in a secured DL NAS Transport PDU.
func dsGSM(t *testing.T, ue *test.RanUeContext, naspdu []byte) nasMessage.Message {
	m, err := test.NASDecode(ue, nasMessage.GetSecHdrType(naspdu), naspdu)
	require.Nil(t, err)
	dl, ok := m.(*nasMessage.DLNASTransport)
	require.True(t, ok, "expected DL NAS Transport, got %T", m)
	gsm, err := nasMessage.Parse(dl.PayloadCntr.Contents, nil)
	require.Nil(t, err)
	return gsm
}

func dsULTeid(t *testing.T, transfer []byte) string {
	var tr ngapIE.PDUSessionResourceSetupRequestTransfer
	require.Nil(t, ngapIE.UnmarshalBinary(transfer, &tr))
	for _, f := range tr.ProtocolIEs.List {
		if f.ULNGUUPTNLInformation != nil {
			gtp := f.ULNGUUPTNLInformation.Choice.(*ngapIE.GTPTunnel)
			return hex.EncodeToString([]byte(gtp.GTPTEID.Value))
		}
	}
	t.Fatal("no UL NG-U UP TNL information")
	return ""
}

// dsDumpUPF prints every PDR and FAR gtp5g holds for the first few SEIDs.
func dsDumpUPF(t *testing.T, tag string) {
	script := `
for seid in 1 2 3 4; do
  for id in $(seq 1 16); do
    echo "upfgtp $seid $id" > /proc/gtp5g/pdr 2>/dev/null &&
      awk '/ID|Precedence|PDI|FAR ID|OHR|UL Packet|DL Packet/' /proc/gtp5g/pdr | tr -s '\t ' ' ' | paste -sd' ' | sed "s/^/  PDR seid=$seid id=$id:/"
    echo "upfgtp $seid $id" > /proc/gtp5g/far 2>/dev/null &&
      awk '/ID|Action|OHC/' /proc/gtp5g/far | tr -s '\t ' ' ' | paste -sd' ' | sed "s/^/  FAR seid=$seid id=$id:/"
  done
done
true`
	out, err := exec.Command("sudo", "bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Logf("dump upf: %v", err)
	}
	t.Logf("DSUPF[%s]\n%s", tag, strings.TrimRight(string(out), "\n"))
}

func dsPing(t *testing.T, upfConn *net.UDPConn, ulTeid, tag string) bool {
	ok := t.Run("ping "+tag, func(t *testing.T) {
		icmpTest(t, upfConn, ulTeid, loIp, EXPECTED_NO_ERROR)
	})
	t.Logf("DSPING[%s] teid=%s ok=%v", tag, ulTeid, ok)
	return ok
}

func dsModReq(t *testing.T, ue *test.RanUeContext, conn *sctp.SCTPConn, modReq []byte, tag string) {
	dsMark(t, tag+" send ModReq")
	dsSendNAS(t, ue, conn, ulNASTransportSM(modReq))

	m := dsRecv(t, conn)
	switch msg := m.(type) {
	case *ngapMessage.PDUSessionResourceModifyRequest:
		item := msg.PDUSessionResourceModifyListModReq.List[0]
		gsm := dsGSM(t, ue, []byte(item.NASPDU.Value))
		t.Logf("DSNGAP[%s] PDUSessionResourceModifyRequest N1=%T transfer=%x",
			tag, gsm, []byte(*item.PDUSessionResourceModifyRequestTransfer))

		sendMsg, err := ngapTestpacket.BuildPDUSessionResourceModifyResponse(ue.AmfUeNgapId, ue.RanUeNgapId).MarshalBinary()
		require.Nil(t, err)
		_, err = conn.Write(sendMsg)
		require.Nil(t, err)
		time.Sleep(300 * time.Millisecond)

		if _, isCmd := gsm.(*nasMessage.PDUSessModCmd); isCmd {
			dsMark(t, tag+" send ModComplete")
			dsSendNAS(t, ue, conn, ulNASTransportSM(nasTestpacket.GetPduSessionModificationComplete(dsPSI)))
		}
	case *ngapMessage.DownlinkNASTransport:
		t.Logf("DSNGAP[%s] DownlinkNASTransport N1=%T", tag, dsGSM(t, ue, []byte(msg.NASPDU.Value)))
	default:
		t.Fatalf("unexpected NGAP %T after ModReq", m)
	}
	time.Sleep(1 * time.Second)
}

func runDSModReq(t *testing.T, modReq func() []byte) {
	MranConn, SranConn := connectRANsToAMF(t)
	require.NotNil(t, MranConn)
	defer MranConn.Close()
	defer SranConn.Close()
	MupfConn, SupfConn := connectRANsToUPF(t)
	require.NotNil(t, MupfConn)
	defer MupfConn.Close()
	defer SupfConn.Close()
	nGsSetup(t, MranConn, SranConn)

	ue := newUEAndInitialRegistration(t, MranConn)
	defer test.DelUeFromMongoDB(t, ue, servingPlmnId)

	// Establishment, keeping the UL TEID the RAN was given.
	dsMark(t, "establish")
	dsSendNAS(t, ue, MranConn, nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(
		dsPSI, nasIE.ReqType_InitialReq, "internet", &sNssaiDS))
	setupReq, ok := dsRecv(t, MranConn).(*ngapMessage.PDUSessionResourceSetupRequest)
	require.True(t, ok)
	ulTeid := dsULTeid(t, []byte(*setupReq.PDUSessionResourceSetupListSUReq.List[0].PDUSessionResourceSetupRequestTransfer))
	t.Logf("DSNGAP[establish] UL TEID=%s", ulTeid)
	sendMsg, err := ngapTestpacket.BuildPDUSessionResourceSetupResponseWithDC(
		dsPSI, ue.AmfUeNgapId, ue.RanUeNgapId, mranN3Addr, mranDLTeid, "", "").MarshalBinary()
	require.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	require.Nil(t, err)
	time.Sleep(1 * time.Second)
	dsDumpUPF(t, "after establish")
	dsPing(t, MupfConn, ulTeid, "after establish")

	if modReq != nil {
		dsModReq(t, ue, MranConn, modReq(), "modreq1")
		dsDumpUPF(t, "after modreq1")
		dsPing(t, MupfConn, ulTeid, "after modreq1")

		dsModReq(t, ue, MranConn, modReq(), "modreq2")
		dsDumpUPF(t, "after modreq2")
		dsPing(t, MupfConn, ulTeid, "after modreq2")
	}

	// AN release then Service Request: the first procedures after the ModReqs
	// that send PFCP and rebuild N2 information from the data path pool.
	dsMark(t, "AN release")
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, []int64{dsPSI})
	require.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	require.Nil(t, err)
	_, ok = dsRecv(t, MranConn).(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok)
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	require.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	require.Nil(t, err)
	time.Sleep(1 * time.Second)
	dsDumpUPF(t, "after AN release")

	dsMark(t, "service request")
	pdu := nasTestpacket.GetServiceRequest(nasIE.SvcType_Data)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nasMessage.SecHdrTypeIntegrityProtected, true, false)
	require.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	require.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	require.Nil(t, err)
	m := dsRecv(t, MranConn)
	icsReq, ok := m.(*ngapMessage.InitialContextSetupRequest)
	require.True(t, ok, "expected InitialContextSetupRequest, got %T", m)
	ue.AmfUeNgapId = icsReq.AMFUENGAPID.Value
	if icsReq.PDUSessionResourceSetupListCxtReq != nil {
		ulTeid = dsULTeid(t, []byte(*icsReq.PDUSessionResourceSetupListCxtReq.List[0].PDUSessionResourceSetupRequestTransfer))
		t.Logf("DSNGAP[service request] UL TEID=%s", ulTeid)
	} else {
		t.Logf("DSNGAP[service request] no PDUSessionResourceSetupListCxtReq")
	}
	// The sample response carries PSI 5; point it at this session.
	icsRsp := ngapTestpacket.BuildInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId, mranN3Addr, nil).(*ngapMessage.InitialContextSetupResponse)
	icsRsp.PDUSessionResourceSetupListCxtRes.List[0].PDUSessionID.Value = dsPSI
	sendMsg, err = icsRsp.MarshalBinary()
	require.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	require.Nil(t, err)
	time.Sleep(1 * time.Second)
	dsDumpUPF(t, "after service request")
	dsPing(t, MupfConn, ulTeid, "after service request")

	dsMark(t, "release")
	dsSendNAS(t, ue, MranConn, nasTestpacket.GetUlNasTransport_PduSessionReleaseRequest(dsPSI))
	m = dsRecv(t, MranConn)
	t.Logf("DSNGAP[release] %T", m)
	sendMsg, err = test.GetPDUSessionResourceReleaseResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	require.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	require.Nil(t, err)
	time.Sleep(300 * time.Millisecond)
	dsSendNAS(t, ue, MranConn, nasTestpacket.GetUlNasTransport_PduSessionReleaseComplete(
		dsPSI, nasIE.ReqType_ExistingPDUSess, "internet", &sNssaiDS))
	time.Sleep(1 * time.Second)
	dsDumpUPF(t, "after release")

	NfTerminate()
}

// TestDSModReqControl skips the ModReqs to show the baseline.
func TestDSModReqControl(t *testing.T)      { runDSModReq(t, nil) }
func TestDSModReqNoEPCO(t *testing.T)       { runDSModReq(t, modReqNoEPCO) }
func TestDSModReqKnownEPCO(t *testing.T)    { runDSModReq(t, modReqKnownEPCO) }
func TestDSModReqOperatorEPCO(t *testing.T) { runDSModReq(t, modReqOperatorEPCO) }
