import './styles.css'
import { mountIntro } from './ui/intro'
import { mountAct1 } from './ui/act1'
import { mountAct2 } from './ui/act2'
import { mountAct3 } from './ui/act3'
import { mountAct4 } from './ui/act4'
import { mountAct5 } from './ui/act5'
import { mountAct6 } from './ui/act6'
import { mountProperties } from './ui/properties'
import { mountScope } from './ui/scope'

/**
 * Story order: rebuild a pulse, chain pulses, skip across a month, find where
 * the signature stops vouching; then the threshold beacon, why its output is
 * unique, and the four properties side by side. Scope last.
 */
const host = document.getElementById('exhibits')
if (host) {
  mountIntro(host)
  mountAct1(host)
  mountAct2(host)
  mountAct3(host)
  mountAct4(host)
  mountAct5(host)
  mountAct6(host)
  void mountProperties(host).then(() => {
    mountScope(host)
    host.setAttribute('data-ready', 'true')
  })
}
