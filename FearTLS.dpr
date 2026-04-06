// FearTLS
// © 2024-2026 FearDC

library FearTLS;

{$R *.res}

uses
  System.Classes,
  System.SysUtils,
  System.StrUtils,
  System.IOUtils,

  {$IFDEF MSWINDOWS}
  WinAPI.Windows,
  WinAPI.WinSock,
  {$ELSE}
  Posix.Signal,
  Posix.SysSocket,
  {$ENDIF}

  IdGlobal,
  IdStack,
  IdContext,
  IdMappedPortTCP,
  IdCustomTCPServer,
  TaurusTLS;

type
  TFearConf = record
	  FAddr: String;
	  FPort: Integer;
	  FHost: String;
	  FCert: String;
	  FKey: String;
	  FLog: Boolean;
	  FWait: Integer;
	  FVer: Integer;
	  FSend: Boolean;
  end;

  TBaseConf = record
	  FAddr: PAnsiChar;
	  FPort: Integer;
	  FHost: PAnsiChar;
	  FCert: PAnsiChar;
	  FKey: PAnsiChar;
	  FLog: Boolean;
	  FWait: Integer;
	  FVer: Integer;
	  FSend: Boolean;
  end;

  PBaseConf = ^TBaseConf;

  {$IFNDEF MSWINDOWS}
  TTimeVal = record
    tv_sec, tv_usec: LongInt;
  end;
  {$ENDIF}

  TFearTLS = class(TIdMappedPortTCP)
    private
      FSSL: TTaurusTLSServerIOHandler;

      procedure OnConnectIn(AConn: TIdContext);
      procedure OnConnectOut(AConn: TIdContext);
      procedure OnDisconnectIn(AConn: TIdContext);
      procedure OnDisconnectOut(AConn: TIdContext);
      procedure OnErrorClient(AConn: TIdContext; AErr: Exception);
      procedure OnErrorServer(AConn: TIdListenerThread; AErr: Exception);

    public
      constructor Create;
      destructor Destroy; override;
  end;

const
  APP_NAME = 'FearTLS';
  APP_VER = '0.0.1.2';

var
  FConf: TFearConf;

procedure SyncLog(const ALine: String; const APref: Boolean = True; const AEnd: Boolean = True);
var
  LLine: String;
  LEnd: Boolean;
begin
  LLine := ALine;

  if APref then
    LLine := '[' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', System.SysUtils.Now) + '][' + APP_NAME + '] ' + LLine;

  LEnd := AEnd;

  TThread.Synchronize(nil,
    procedure
    begin
      if LEnd then
        System.WriteLn(LLine)
      else
        System.Write(LLine);
    end
  );
end;

constructor TFearTLS.Create;
begin
  inherited Create;

  FSSL := TTaurusTLSServerIOHandler.Create;

  FSSL.DefaultCert.PublicKey := FConf.FCert; // todo: cert tool - ics95 for windows and ics10 for linux
  FSSL.DefaultCert.PrivateKey := FConf.FKey;
  FSSL.SSLOptions.UseSystemRootCACertificateStore := False;
  FSSL.SSLOptions.VerifyMode := [];
  FSSL.SSLOptions.Mode := TTaurusTLSSSLMode.sslmServer;

  case FConf.FVer of // tls 1.0 .. 1.3
    0: FSSL.SSLOptions.MinTLSVersion := TTaurusTLSSSLVersion.TLSv1;
    1: FSSL.SSLOptions.MinTLSVersion := TTaurusTLSSSLVersion.TLSv1_1;
    2: FSSL.SSLOptions.MinTLSVersion := TTaurusTLSSSLVersion.TLSv1_2;
    3: FSSL.SSLOptions.MinTLSVersion := TTaurusTLSSSLVersion.TLSv1_3;
  end;

  if FSSL.SSLOptions.MinTLSVersion = TTaurusTLSSSLVersion.TLSv1 then // strongdc
    FSSL.SSLOptions.CipherList := 'ALL:@SECLEVEL=0';

  IOHandler := FSSL;

  OnBeforeConnect := OnConnectIn;
  OnOutboundConnect := OnConnectOut;
  OnDisconnect := OnDisconnectIn;
  OnOutboundDisconnect := OnDisconnectOut;
  OnException := OnErrorClient;
  OnListenException := OnErrorServer;
end;

destructor TFearTLS.Destroy;
begin
  OnBeforeConnect := nil;
  OnOutboundConnect := nil;
  OnDisconnect := nil;
  OnOutboundDisconnect := nil;
  OnException := nil;
  OnListenException := nil;

  IOHandler := nil;

  FSSL.Shutdown;
  FSSL.Free;

  inherited Destroy;
end;

procedure TFearTLS.OnConnectIn(AConn: TIdContext);
var
  {$IFDEF MSWINDOWS}
  LTime: DWord;
  {$ELSE}
  LTime: TTimeVal;
  {$ENDIF}

  LPeek: Array [0..1] of Byte;
begin
  if not Assigned(AConn) then
    Exit;

  //(AConn.Connection.IOHandler as TTaurusTLSIOHandlerSocket).PassThrough := False; // todo

  if FConf.FWait < 1 then // tls only
    Exit;

  {$IFDEF MSWINDOWS}
  LTime := FConf.FWait; // milliseconds
  WinAPI.WinSock.SetSockOpt(AConn.Binding.Handle, WinAPI.WinSock.SOL_SOCKET, WinAPI.WinSock.SO_RCVTIMEO, PAnsiChar(@LTime), SizeOf(LTime));
  {$ELSE}
  LTime.tv_sec := 0;
  LTime.tv_usec := FConf.FWait * 1000; // microseconds
  Posix.SysSocket.SetSockOpt(AConn.Binding.Handle, Posix.SysSocket.SOL_SOCKET, Posix.SysSocket.SO_RCVTIMEO, &LTime, SizeOf(LTime));
  {$ENDIF}

  (AConn.Connection.IOHandler as TTaurusTLSIOHandlerSocket).PassThrough := not ((
    {$IFDEF MSWINDOWS}
    (WinAPI.WinSock.Recv(AConn.Binding.Handle, LPeek, 2, WinAPI.WinSock.MSG_PEEK) = 2)
    {$ELSE}
    (Posix.SysSocket.Recv(AConn.Binding.Handle, LPeek, 2, Posix.SysSocket.MSG_PEEK) = 2)
    {$ENDIF}
  ) and (LPeek[0] = 22) and (LPeek[1] = 03)); // magic bytes

  {$IFDEF MSWINDOWS} // reset
  LTime := 0;
  WinAPI.WinSock.SetSockOpt(AConn.Binding.Handle, WinAPI.WinSock.SOL_SOCKET, WinAPI.WinSock.SO_RCVTIMEO, PAnsiChar(@LTime), SizeOf(LTime));
  {$ELSE}
  LTime.tv_sec := 0;
  LTime.tv_usec := 0;
  Posix.SysSocket.SetSockOpt(AConn.Binding.Handle, Posix.SysSocket.SOL_SOCKET, Posix.SysSocket.SO_RCVTIMEO, &LTime, SizeOf(LTime));
  {$ENDIF}

  {
  if Assigned(AConn.Connection.IOHandler) then begin
    AConn.Connection.IOHandler.ReadTimeout := 10 * 60 * 1000; // 10 m
    AConn.Connection.IOHandler.ConnectTimeout := 30 * 1000; // 30 s
  end;

  if Assigned(AConn.OutboundClient) then begin // todo: move to on outbound client connected
    AConn.OutboundClient.IOHandler.ReadTimeout := AConn.Connection.IOHandler.ReadTimeout;
    AConn.OutboundClient.IOHandler.ConnectTimeout := AConn.Connection.IOHandler.ConnectTimeout;
  end;
  }
end;

procedure TFearTLS.OnConnectOut(AConn: TIdContext);
var
  LData, LAddr: String;
  LVers, LPort: Integer;
begin
  if not FConf.FSend then
    Exit;

  if not Assigned(AConn) then
    Exit;

  LAddr := AConn.Binding.PeerIP;
  LData := '$MyIP ' + LAddr + ' ';
  LVers := -1;

  if not (AConn.Connection.IOHandler as TTaurusTLSIOHandlerSocket).PassThrough then begin
    case (AConn.Connection.IOHandler as TTaurusTLSIOHandlerSocket).SSLSocket.SSLProtocolVersion of
      TTaurusTLSSSLVersion.TLSv1: LVers := 0;
      TTaurusTLSSSLVersion.TLSv1_1: LVers := 1;
      TTaurusTLSSSLVersion.TLSv1_2: LVers := 2;
      TTaurusTLSSSLVersion.TLSv1_3: LVers := 3;
    end;
  end;

  if LVers > -1 then
    LData := LData + '1.' + LVers.ToString
  else
    LData := LData + '0.0';

  LData := LData + '|';

  try
    if Assigned((AConn as TIdMappedPortContext).OutboundClient) then
      (AConn as TIdMappedPortContext).OutboundClient.IOHandler.Write(LData); // todo: timeout, (AConn as TIdMappedPortContext).OutboundClient.Socket.Write(LData)

  except
    on LErr: Exception do begin
      if FConf.FLog then begin
        LPort := AConn.Binding.PeerPort;
        SyncLog(Format('Error on write to client connection %s:%d: %s', [LAddr, LPort, LErr.Message]));
      end;

      if AConn.Connection.Connected then
        AConn.Connection.Disconnect;

      if Assigned((AConn as TIdMappedPortContext).OutboundClient) and (AConn as TIdMappedPortContext).OutboundClient.Connected then
        (AConn as TIdMappedPortContext).OutboundClient.Disconnect;
    end;
  end;
end;

procedure TFearTLS.OnDisconnectIn(AConn: TIdContext); // todo: users never disconnect, todo: we need to check for data on source and outbound client on execute
var
  LAddr: String;
  LPort: Integer;
begin
  if not Assigned(AConn) then
    Exit;

  if FConf.FLog then begin
    LAddr := AConn.Binding.PeerIP;
    LPort := AConn.Binding.PeerPort;
    SyncLog(Format('Disconnected inbound connection: %s:%d', [LAddr, LPort]));
  end;

  if AConn.Connection.Connected then
    AConn.Connection.Disconnect;

  if Assigned((AConn as TIdMappedPortContext).OutboundClient) and (AConn as TIdMappedPortContext).OutboundClient.Connected then
    (AConn as TIdMappedPortContext).OutboundClient.Disconnect;
end;

procedure TFearTLS.OnDisconnectOut(AConn: TIdContext);
var
  LAddr: String;
  LPort: Integer;
begin
  if not Assigned(AConn) then
    Exit;

  if FConf.FLog then begin
    LAddr := AConn.Binding.PeerIP;
    LPort := AConn.Binding.PeerPort;
    SyncLog(Format('Disconnected outbound connection: %s:%d', [LAddr, LPort]));
  end;

  if AConn.Connection.Connected then
    AConn.Connection.Disconnect;

  if Assigned((AConn as TIdMappedPortContext).OutboundClient) and (AConn as TIdMappedPortContext).OutboundClient.Connected then
    (AConn as TIdMappedPortContext).OutboundClient.Disconnect;
end;

procedure TFearTLS.OnErrorClient(AConn: TIdContext; AErr: Exception);
var
  LAddr, LErr: String;
  LPort: Integer;
begin
  if not Assigned(AConn) then
    Exit;

  if FConf.FLog then begin
    LAddr := AConn.Binding.PeerIP;
    LPort := AConn.Binding.PeerPort;

    if Assigned(AErr) then
      LErr := AErr.Message
    else
      LErr := 'Unknown error';

    SyncLog(Format('Error on client connection %s:%d: %s', [LAddr, LPort, LErr]));
  end;

  if AConn.Connection.Connected then
    AConn.Connection.Disconnect;

  if Assigned((AConn as TIdMappedPortContext).OutboundClient) and (AConn as TIdMappedPortContext).OutboundClient.Connected then
    (AConn as TIdMappedPortContext).OutboundClient.Disconnect;
end;

procedure TFearTLS.OnErrorServer(AConn: TIdListenerThread; AErr: Exception);
var
  LAddr, LErr: String;
  LPort: Integer;
begin
  if not Assigned(AConn) then
    Exit;

  LAddr := AConn.Binding.IP;
  LPort := AConn.Binding.Port;

  if Assigned(AErr) then
    LErr := AErr.Message
  else
    LErr := 'Unknown error';

  SyncLog(Format('Error on server connection %s:%d: %s', [LAddr, LPort, LErr]));
end;

var
  FServ: TFearTLS;

function FearStart(AConf: PBaseConf): Boolean; cdecl;
var
  LList: TArray<String>;
  LPos: Integer;
  LPart, LHost, LPort: String;
begin
  SyncLog(Format('Starting %s %s using %s', [APP_NAME, APP_VER, TaurusTLS.OpenSSLVersion]));

  Result := False;

  // address

  FConf.FAddr := String(AConf.FAddr);

  if not IdStack.GStack.IsIP(FConf.FAddr) then begin
    SyncLog(Format('Invalid hub address specified: %s', [FConf.FAddr]));
    Exit;
  end;

  // port

  FConf.FPort := AConf.FPort;

  if (FConf.FPort < 1) or (FConf.FPort > 65535) then begin
    SyncLog(Format('Invalid hub port specified: %d', [FConf.FPort]));
    Exit;
  end;

  // certificate

  FConf.FCert := String(AConf.FCert);

  if not TFile.Exists(FConf.FCert) then begin
    SyncLog(Format('Invalid certificate file specified: %s', [FConf.FCert]));
    Exit;
  end;

  // key

  FConf.FKey := String(AConf.FKey);

  if not TFile.Exists(FConf.FKey) then begin
    SyncLog(Format('Invalid key file specified: %s', [FConf.FKey]));
    Exit;
  end;

  // host

  FConf.FHost := String(AConf.FHost);
  LList := FConf.FHost.Split([' '], TStringSplitOptions.ExcludeEmpty);

  if Length(LList) < 1 then begin
    SyncLog(Format('Invalid hub hosts specified: %s', [FConf.FHost]));
    Exit;
  end;

  FServ := TFearTLS.Create;

  for LPart in LList do begin
    LPos := LPart.IndexOf(':');

    if LPos = -1 then begin
      SyncLog(Format('Missing address separator: %s', [LPart]));

    end else begin
      LHost := LPart.SubString(0, LPos);
      LPort := LPart.SubString(LPos + 1);

      if not TryStrToInt(LPort, LPos) then begin
        SyncLog(Format('Failed to convert port number: %s', [LPort]));

      end else if (LPos < 1) or (LPos > 65535) then begin
        SyncLog(Format('Specified port is out of range: %d', [LPos]));

      end else if not IdStack.GStack.IsIP(LHost) then begin
        SyncLog(Format('Invalid IP address specified: %s', [LHost]));

      end else begin
        with FServ.Bindings.Add do begin
          IP := LHost;
          Port := LPos;
          IPVersion := IdGlobal.Id_IPv4;
          SyncLog(Format('Listening on address: %s:%d', [LHost, LPos]));
        end;
      end;
    end;
  end;

  if FServ.Bindings.Count < 1 then begin
    SyncLog(Format('Invalid hub hosts specified: %s', [FConf.FHost]));
    Exit;
  end;

  // rest

  FConf.FLog := AConf.FLog;
  FConf.FWait := AConf.FWait;
  FConf.FVer := AConf.FVer;
  FConf.FSend := AConf.FSend;

  FServ.MappedHost := FConf.FAddr;
  FServ.MappedPort := FConf.FPort;
  SyncLog(Format('Proxying to address: %s:%d [%d ms]', [FConf.FAddr, FConf.FPort, FConf.FWait]));
  SyncLog(Format('Error logging is enabled: %s', [IfThen(FConf.FLog, 'Yes', 'No')]));

  FServ.ListenQueue := 1000; // todo: test

  try
    FServ.Active := True;

  except
    on LErr: Exception do begin
      SyncLog(Format('Failed starting server: %s', [LErr.Message]));
      Exit;
    end;
  end;

  Result := FServ.Active;

  {$IFNDEF MSWINDOWS}
  Posix.Signal.Signal(Posix.Signal.SIGPIPE, Posix.Signal.TSignalHandler(Posix.Signal.SIG_IGN));
  {$ENDIF}
end;

procedure FearStop(ACode: Integer); cdecl;
begin
  if not Assigned(FServ) then
    Exit;

  FConf.FLog := False; // avoid flood

  TThread.Synchronize(nil,
    procedure
    var
      LPos: Integer;
      LList: TIdContextList;
    begin
      LList := FServ.Contexts.LockList;

      for LPos := 0 to LList.Count - 1 do
        TIdMappedPortContext(LList[LPos]).Binding.CloseSocket;

      FServ.Contexts.UnlockList;
    end
  );

  FServ.Active := False;
  FServ.Free;

  SyncLog(Format('Stopping %s', [APP_NAME]));
  System.ExitCode := ACode;
end;

exports
  FearStart name 'VH_FearStart',
  FearStop name 'VH_FearStop';

begin
  // nothing to do
end.

// end of file
