import{r as l}from"./index.DLkBFFtG.js";/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const E=e=>e?.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase();/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */function I(e,t,n=[]){if(t==null)throw new Error("[lucide]: iconNode is required when icon name is used");return{name:E(e),size:24,node:t,...n.length>0?{aliases:n}:{}}}/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const j=e=>{let t="",n=!1;for(const o of e){if(o==="-"||o==="_"||o<=" "){n=t.length>0;continue}t.length===0?t+=o.toLowerCase():t+=n?o.toUpperCase():o,n=!1}return t};/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const P=e=>{const t=j(e);return t.charAt(0).toUpperCase()+t.slice(1)};/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const m=(...e)=>e.filter((t,n,o)=>!!t&&t.trim()!==""&&o.indexOf(t)===n).join(" ").trim();/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const c={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":2,"stroke-linecap":"round","stroke-linejoin":"round"};/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */function x(e){return e!=null}function R(e,t={}){const n=t.attributeNames??{},o=i=>n[i]??i,a=e.size??e.width??c.width,h=e.size??e.height??c.height,u=e.aliases?.filter(i=>typeof i=="string"&&i.trim()!=="").map(i=>`lucide-${i}`)??[],f=[...e.name?[`lucide-${e.name}`]:[],...u],s=t.className?.split(" ").filter(Boolean)??[],k=t.includeDefaultClasses===!1?m(...s):m("lucide",...f,...s),b=t.absoluteStrokeWidth?Number(t.strokeWidth??c["stroke-width"])*Number(e.size??e.width??c.width)/Number(t.size??t.width??c.width):t.strokeWidth??c["stroke-width"];return["svg",{...Object.entries(c).reduce((i,[r,d])=>(i[o(r)]=d,i),{}),..."color"in t&&t.color&&{[o("stroke")]:t.color},..."size"in t&&x(t.size)&&{[o("width")]:t.size,[o("height")]:t.size},..."width"in t&&x(t.width)&&{[o("width")]:t.width},..."height"in t&&x(t.height)&&{[o("height")]:t.height},[o("stroke-width")]:b,...k&&{[o("class")]:k},[o("viewBox")]:`0 0 ${a} ${h}`,...t.hasA11yProp===!1?{[o("aria-hidden")]:"true"}:{},..."attributes"in t&&t.attributes},e.node.map(i=>{const[r,d,w]=i,g=t.nonScalingStroke?{[o("vector-effect")]:"non-scaling-stroke",...d}:d;return w?[r,g,w]:[r,g]})]}/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */function _(e,t={}){return R(e,{...t,attributeNames:{...t.attributeNames,class:"className","stroke-width":"strokeWidth","stroke-linecap":"strokeLinecap","stroke-linejoin":"strokeLinejoin","vector-effect":"vectorEffect"}})}/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const D=e=>{for(const t in e)if(t.startsWith("aria-")||t==="role"||t==="title")return!0;return!1},M=l.createContext({}),q=()=>l.useContext(M),F=l.forwardRef(({color:e,size:t,width:n,height:o,strokeWidth:a,absoluteStrokeWidth:h,nonScalingStroke:u,className:f="",children:s,iconNode:k=[],icon:b={node:k,aliases:[],size:24},...C},i)=>{const{size:r=24,strokeWidth:d=2,absoluteStrokeWidth:w=!1,nonScalingStroke:g=!1,color:z="currentColor",className:v=""}=q()??{},A=!!s||D(C),[W,L,p=[]]=_(b,{color:e??z,width:n??t??r,height:o??t??r,strokeWidth:a??d,absoluteStrokeWidth:h??w,nonScalingStroke:u??g,className:m(v,f),hasA11yProp:A,attributes:C});return l.createElement(W,{ref:i,...L},[...p.map(([B,$])=>l.createElement(B,$)),...Array.isArray(s)?s:[s]])});/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */function N(e,t=[],n=[]){const o=typeof e=="string"?I(e,t,n):e,a=l.forwardRef(({className:h,...u},f)=>l.createElement(F,{ref:f,icon:o,className:h,...u}));return o.name&&(a.displayName=P(o.name)),a}/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const y={name:"rotate-ccw-clock",size:24,node:[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8",key:"1357e3"}],["path",{d:"M3 3v5h5",key:"1xhq8a"}],["path",{d:"M12 7v5l4 2",key:"1fdv2h"}]],aliases:["history"]};y.node;const U=N(y);/**
 * @license lucide-react v1.69.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const S={name:"terminal",size:24,node:[["path",{d:"M12 19h8",key:"baeox8"}],["path",{d:"m4 17 6-6-6-6",key:"1yngyt"}]]};S.node;const H=N(S);export{U as R,H as T,N as c};
