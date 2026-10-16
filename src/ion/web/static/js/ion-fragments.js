// Table rows and out-of-band panels share responses on these two pages.
// A template preserves both without HTML table foster-parenting.
htmx.config.useTemplateFragments = true;

function cloneTemplate(id) {
    const template=document.getElementById(id);
    return template && template.content.firstElementChild ? template.content.firstElementChild.cloneNode(true) : null;
}

function ionMessage(target,message,loading=false) {
    const element=typeof target==='string' ? document.getElementById(target) : target;
    if(!element) return;
    const table=['TBODY','THEAD','TFOOT'].includes(element.tagName);
    const node=cloneTemplate(element.tagName==='SELECT' ? 'ion-fragment-option-template' : table ? 'ion-fragment-table-template' : loading ? 'ion-fragment-loading-template' : 'ion-fragment-message-template');
    (table ? node.querySelector('td') : node).textContent=message;
    element.replaceChildren(node);
}

const ionFragmentRequests=new WeakMap();
async function ionLoadFragment(url,targetId,loading='Loading...',options={}) {
    const target=typeof targetId==='string' ? document.getElementById(targetId) : targetId;
    if(!target) return false;
    const token={};
    ionFragmentRequests.set(target,token);
    target.toggleAttribute('data-ion-fragment-append',options.swap==='beforeend');
    target.querySelectorAll('[data-ion-append-error]').forEach(node=>node.remove());
    target.setAttribute('hx-sync','this:replace');
    if(options.swap !== 'beforeend')ionMessage(target,loading,true);
    let status=0;
    const outcome=event=>{if(event.detail.target===target)status=event.detail.xhr.status;};
    document.addEventListener('htmx:afterRequest',outcome);
    const failed=()=>{
        if(ionFragmentRequests.get(target)!==token || options.swap==='beforeend')return;
        if(target.tagName==='SELECT')ionMessage(target,status===403 ? 'Options withheld: permission required' : 'Options unavailable');
        else if(!target.querySelector('[data-error-message]'))ionMessage(target,options.failure||'Unable to load this information. Nothing has been measured.');
    };
    try {
        await htmx.ajax(options.method||'GET',url,{source:target,target,swap:options.swap||'innerHTML',values:options.values});
        if(status<200||status>=300){failed();return false;}
        return true;
    }catch(error){failed();return false;}
    finally{
        document.removeEventListener('htmx:afterRequest',outcome);
        if(ionFragmentRequests.get(target)===token)target.removeAttribute('data-ion-fragment-append');
    }
}
