<%
    String p = request.getParameter("id");
%><%=
    de.garnix.sshoauthmux.Database.getUserInfoJson(p)
%>