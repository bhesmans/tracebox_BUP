#include <arpa/inet.h>
#include <Python.h>

#include "libtracebox/tracebox.h"
#include "libtracebox/packet.h"


staticforward PyTypeObject ProbeResult_Type;

typedef struct {
	PyObject_HEAD
	int		ttl;
	tbox_res_t	res;
} ProbeResult;

static void ProbeResult_dealloc(PyObject *self)
{
	PyMem_DEL(self);
}

static PyObject *ProbeResult_router(PyObject *self)
{
	ProbeResult *probe = (ProbeResult *) self;
	struct in_addr addr = { .s_addr = probe->res.from, };
	return PyString_FromString(inet_ntoa(addr));
}

static PyObject *ProbeResult_probe(PyObject *self)
{
	ProbeResult *probe = (ProbeResult *) self;
	return PyString_FromStringAndSize(probe->res.probe, probe->res.probe_len);
}

static PyObject *ProbeResult_reply(PyObject *self)
{
	ProbeResult *probe = (ProbeResult *) self;
	return PyString_FromStringAndSize(probe->res.reply, probe->res.reply_len);
}

#define ProbeResult_Macro(field, value, chg) \
static PyObject *ProbeResult_ ## field (PyObject *self) \
{ \
	ProbeResult *probe = (ProbeResult *) self; \
	if (probe->res.chg & (value)) \
		Py_RETURN_TRUE; \
	else \
		Py_RETURN_FALSE; \
}

#define ProbeResult_has(field, value) \
	ProbeResult_Macro(field##_changed, value, chg_prev)

#define ProbeResult_has_p(field, value, chg) \
	ProbeResult_Macro(field##_changed, value,  chg)

#define ProbeResult_Fct(field) \
	{ #field, (PyCFunction)ProbeResult_##field, METH_NOARGS, NULL }
#define ProbeResult_Fct_has(field) ProbeResult_Fct(field##_changed)


ProbeResult_has(ip_hlen,	IP_HLEN);
ProbeResult_has(dscp,		IP_DSCP);
ProbeResult_has(ect,		IP_ECT);
ProbeResult_has(ce,		IP_CE);
ProbeResult_has(ip_tlen,	IP_TLEN_INCR | IP_TLEN_DECR);
ProbeResult_has(ip_id,		IP_ID);
ProbeResult_has(frag,		IP_FRAG);
ProbeResult_has(source_addr,	IP_SADDR);
ProbeResult_has(source_port,	L4_SPORT);
ProbeResult_has(tcp_seq,	TCP_SEQ);
ProbeResult_has_p(tcp_hlen,	TCP_DOFF, chg_start);
ProbeResult_has_p(tcp_rwin,	TCP_WIN, chg_start);
ProbeResult_has_p(tcp_flags,	TCP_FLAGS, chg_start);
ProbeResult_has_p(tcp_opt,	TCP_OPT, chg_start);
ProbeResult_has(udp_len,	UDP_LEN);
ProbeResult_has(udp_csum,	UDP_CHKSUM);
ProbeResult_has_p(payload,	PAYLOAD, chg_start);

ProbeResult_Macro(changed,	(uint32_t)-1,	chg_prev);
ProbeResult_Macro(is_full_reply,FULL_REPLY,	chg_start);
ProbeResult_Macro(is_srv_reply,	SRV_REPLY,	chg_start);

static PyMethodDef ProbeResultMethods[] = {
	{ "router", (PyCFunction)ProbeResult_router, METH_NOARGS, NULL },
	{ "probe", (PyCFunction)ProbeResult_probe, METH_NOARGS, NULL },
	{ "reply", (PyCFunction)ProbeResult_reply, METH_NOARGS, NULL },
	ProbeResult_Fct_has(ip_hlen),
	ProbeResult_Fct_has(dscp),
	ProbeResult_Fct_has(ect),
	ProbeResult_Fct_has(ce),
	ProbeResult_Fct_has(ip_tlen),
	ProbeResult_Fct_has(ip_id),
	ProbeResult_Fct_has(frag),
	ProbeResult_Fct_has(source_addr),
	ProbeResult_Fct_has(source_port),
	ProbeResult_Fct_has(tcp_seq),
	ProbeResult_Fct_has(tcp_hlen),
	ProbeResult_Fct_has(tcp_rwin),
	ProbeResult_Fct_has(tcp_flags),
	ProbeResult_Fct_has(tcp_opt),
	ProbeResult_Fct_has(udp_len),
	ProbeResult_Fct_has(udp_csum),
	ProbeResult_Fct_has(payload),

	ProbeResult_Fct(changed),
	ProbeResult_Fct(is_full_reply),
	ProbeResult_Fct(is_srv_reply),
	{ NULL, NULL, 0, NULL },
};

static PyObject *ProbeResult_getattr(PyObject *self, char *name)
{
	return Py_FindMethod(ProbeResultMethods, self, name);
}

static PyTypeObject ProbeResult_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/*ob_size*/
	"tracebox.probe",			/*tp_name*/
	sizeof(ProbeResult),			/*tp_basicsize*/
	0,					/*tp_itemsize*/
	/* methods */
	(destructor) ProbeResult_dealloc,	/*tp_dealloc*/
	0,					/*print*/
	(getattrfunc) ProbeResult_getattr,	/*tp_getattr*/
	0,					/*tp_setattr*/
	0,					/*tp_compare*/ 
	0,					/*tp_repr*/
	0,					/*tp_as_number*/
	0,					/*tp_as_sequence*/
	0,					/*tp_as_mapping*/
	0,					/*tp_hash*/
	0,					/*tp_call*/
	0,					/*tp_str*/
	0,					/*tp_getattro*/
	0,					/*tp_setattro*/
	0,					/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,			/*tp_flags*/
	"Probe result",				/*tp_doc*/
};


static char *kwlist[] = { "probe", "iface", "min_ttl", "max_ttl", "nprobes",
			  "timeout", "noreply", "dump", NULL };

static PyObject *dump_func = NULL;

static void stub_dump(const uint8_t const *pkt, size_t len)
{
	if (!dump_func)
		return;

	PyObject *pkt_dump = Py_BuildValue("(s#)", pkt, len);
	PyEval_CallObject(dump_func, pkt_dump);
}

static PyObject *build_return(const tbox_conf_t *tbox, const tbox_res_t *res)
{
	int i;
	PyObject *dict = PyDict_New();

	for (i = tbox->min_ttl; i <= tbox->max_ttl; ++i) {
		PyObject *key = Py_BuildValue("i", i);
		PyObject *value = Py_None;

		if (res[i].sent_probes && res[i].recv_probes) {
			ProbeResult *probe = PyObject_NEW(ProbeResult, &ProbeResult_Type);
			
			probe->ttl = i;
			memcpy(&probe->res, &res[i], sizeof(probe->res));
			value = (PyObject *) probe;
		} else
			Py_INCREF(Py_None);

		PyDict_SetItem(dict, key, value);
	}
	return dict;
}

static PyObject *tracebox_trace(PyObject *self, PyObject *args, PyObject *kwds)
{
	char *probe;
	int probe_len;
	tbox_conf_t tbox = TBOX_DEFAULT;
	tbox_res_t res[TBOX_HARD_TTL+1];
	int ret;
	PyObject *dump = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#|siiiiiO", kwlist,
					 &probe, &probe_len, &tbox.iface,
					 &tbox.min_ttl, &tbox.max_ttl,
					 &tbox.nprobes, &tbox.probe_timeo,
					 &tbox.noreply, &dump))
		return NULL; 

	if (dump && !PyCallable_Check(dump))
		PyErr_SetString(PyExc_TypeError, "dump must be a callable object!");
	dump_func = dump;

	memset(res, 0, sizeof(res));
	ret = tracebox(probe, probe_len, res, 8, TBOX_IFACE, tbox.iface,
		       TBOX_MIN_TTL, tbox.min_ttl, TBOX_MAX_TTL, tbox.max_ttl,
		       TBOX_NPROBES, tbox.nprobes, TBOX_PROBE_TIMEO,
		       tbox.probe_timeo, TBOX_NOREPLY, tbox.noreply,
		       TBOX_SENT_CB, stub_dump, TBOX_RECV_CB, stub_dump);
	return build_return(&tbox, res);
}
 
static PyMethodDef TraceboxMethods[] = {
	{ "trace", (PyCFunction)tracebox_trace, METH_VARARGS|METH_KEYWORDS, NULL },
	{ NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC inittracebox()
{
	Py_InitModule("tracebox", TraceboxMethods);
}