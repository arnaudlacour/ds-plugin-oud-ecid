package com.pingidentity.ds.plugin;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.directory.sdk.common.operation.*;
import com.unboundid.directory.sdk.common.types.ActiveOperationContext;
import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.directory.sdk.ds.api.Plugin;
import com.unboundid.directory.sdk.ds.config.PluginConfig;
import com.unboundid.directory.sdk.ds.types.DirectoryServerContext;
import com.unboundid.directory.sdk.ds.types.PreParsePluginResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.unboundidds.controls.OperationPurposeRequestControl;
import com.unboundid.util.args.ArgumentParser;

import java.util.ArrayList;
import java.util.List;

public class ECID extends Plugin {
    public static final String ECID_OID = "2.16.840.1.113894.1.8.31";
    private DirectoryServerContext serverContext;

    @Override
    public String getExtensionName() {
        return "ds-plugin-oud-ecid";
    }

    @Override
    public String[] getExtensionDescription() {
        return new String[]{"Handles inbound ECID control and convert to Operation Purpose control"};
    }

    @Override
    public void initializePlugin(DirectoryServerContext serverContext, PluginConfig config, ArgumentParser parser) throws LDAPException {
        this.serverContext = serverContext;
        serverContext.registerSupportedControlOID(ECID_OID);
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableAddRequest request, UpdatableAddResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableAbandonRequest request) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableSimpleBindRequest request, UpdatableBindResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableSASLBindRequest request, UpdatableBindResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableCompareRequest request, UpdatableCompareResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableDeleteRequest request, UpdatableDeleteResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableExtendedRequest request, UpdatableExtendedResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableModifyDNRequest request, UpdatableModifyDNResult result) {
        if (request == null ) {
            return PreParsePluginResult.SUCCESS;
        }
        request.setRequestControls(processControlList(request.getRequestControls()));
        return PreParsePluginResult.SUCCESS;
    }

    private List<Control> processControlList(List<Control> inboundControlList){
        if (inboundControlList == null){
            return null;
        }
        if ( hasControl(inboundControlList,OperationPurposeRequestControl.OPERATION_PURPOSE_REQUEST_OID)){
            return inboundControlList;
        }
        if ( ! hasControl(inboundControlList, ECID_OID)){
            return inboundControlList;
        }

        List<Control> outboundControlList=new ArrayList<>(inboundControlList.size());
        for (Control c: inboundControlList){
            if (ECID_OID.equals(c.getOID())){
                outboundControlList.add(convertECIDtoOperationPurpose(c));
            } else {
                outboundControlList.add(c);
            }
        }
        return outboundControlList;
    }

    private Control convertECIDtoOperationPurpose(Control ecid){
        if (ecid == null) {
            return null;
        }
        ASN1OctetString ecidValue = ecid.getValue();
        if ( ecidValue == null) {
            return null;
        }
        // to be truly useful, the ASN.1 encoding of the ECID control will need to be decoded and re-encoded
        return new OperationPurposeRequestControl(false,"Oracle","1.0",null,ecidValue.stringValue());
    }

    private boolean hasControl(List<Control> controlList, String oid){
        for (Control c: controlList){
            if ( c.getOID().equals(oid) ){
                return true;
            }
        }
        return false;
    }
}
