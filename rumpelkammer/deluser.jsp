<%
    String p = request.getParameter("id");
%><%=
    de.garnix.sshoauthmux.Database.deleteUid( Integer.parseUnsignedInt(p,16))
%>