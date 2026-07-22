export default {
    id: 'static/external-demo', title: 'demo', layer: 'static',
    run(ctx){ ctx.report({ ruleId:'demo-rule', severity:'low', title:'external probe ran', file:null, line:1, confidence:1 }); }
  };
