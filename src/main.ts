import './styles.css'
import { mountIntro } from './ui/intro'
import { mountGuided } from './ui/guided'
import { mountAct1 } from './ui/act1'
import { mountAct2 } from './ui/act2'
import { mountAct3 } from './ui/act3'
import { mountFinding } from './ui/finding'
import { mountAct4 } from './ui/act4'
import { mountAct5 } from './ui/act5'
import { mountAct6 } from './ui/act6'
import { mountProperties } from './ui/properties'
import { mountScope } from './ui/scope'

/**
 * Story order: the plain-language intro, then the 90-second guided experiment
 * (verify → break → everything passes → threshold contrast), then the six
 * acts as the expert route — with the live deployment finding beside Act 4 —
 * and the property comparison as the ending. Scope last.
 */
const host = document.getElementById('exhibits')
if (host) {
  mountIntro(host)
  mountGuided(host)
  mountAct1(host)
  mountAct2(host)
  mountAct3(host)
  const findingSlot = document.createElement('div')
  host.appendChild(findingSlot)
  mountAct4(host)
  mountAct5(host)
  mountAct6(host)
  void Promise.all([mountFinding(findingSlot), mountProperties(host)]).then(() => {
    mountScope(host)
    host.setAttribute('data-ready', 'true')
  })
}
